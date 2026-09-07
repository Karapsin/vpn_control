/* VPN Control's per-job Darwin worker. Built by macOS packaging, never checked in as a binary.
 * No command interpreter consumes package/request fields. Original-user relaunch is a separate
 * process which retains the original login context and never acquires administrator credentials.
 */
#define _DARWIN_C_SOURCE 1
#include <CoreFoundation/CoreFoundation.h>
#include <CommonCrypto/CommonDigest.h>
#include <sys/acl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <libproc.h>
#include <copyfile.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <uuid/uuid.h>
#include "install_watcher_group.h"

enum { MAX_REQUEST = 16384, MAX_PINS = 1024 };
struct generation { pid_t pid; uid_t uid; uint64_t seconds, micros; };
struct request {
    char job[37], package[PATH_MAX], launcher[PATH_MAX], workspace[PATH_MAX];
    char sha256[65], bundle[PATH_MAX];
    struct generation owner, frontend;
    uint64_t package_size;
    bool machine;
};
struct pins { int descriptors[MAX_PINS]; size_t count; };

static void (*failure_handler)(const char *message);
static void fail(const char *message) {
    if (failure_handler) { void (*handler)(const char *) = failure_handler; failure_handler = NULL; handler(message); }
    fprintf(stderr, "%s\n", message); exit(2);
}
static void require(bool condition, const char *message) { if (!condition) fail(message); }
static void retain(struct pins *pins, int fd) {
    require(fd >= 0 && pins->count < MAX_PINS, "UNAVAILABLE");
    pins->descriptors[pins->count++] = fd;
}
static void release(struct pins *pins) {
    while (pins->count) close(pins->descriptors[--pins->count]);
}
static uint64_t number(const char *text, bool zero) {
    require(text && *text && (text[0] != '0' || text[1] == 0), "INVALID_ARGUMENT");
    for (const char *p = text; *p; ++p) require(*p >= '0' && *p <= '9', "INVALID_ARGUMENT");
    errno = 0;
    char *end = NULL;
    unsigned long long value = strtoull(text, &end, 10);
    require(errno == 0 && end && !*end && (zero || value), "INVALID_ARGUMENT");
    return (uint64_t)value;
}
static void text_copy(char *out, size_t capacity, const char *value) {
    require(value && strlen(value) < capacity, "INVALID_ARGUMENT");
    memcpy(out, value, strlen(value) + 1);
}
static void path_check(const char *path) {
    require(path && path[0] == '/' && path[1] && strlen(path) < PATH_MAX, "INVALID_ARGUMENT");
    for (const unsigned char *p = (const unsigned char *)path; *p; ++p)
        require(*p >= 32 && *p != 127, "INVALID_ARGUMENT");
    require(!strstr(path, "//") && !strstr(path, "/../") && !strstr(path, "/./"), "INVALID_ARGUMENT");
    size_t n = strlen(path);
    require(path[n-1] != '/' && strcmp(path+n-2, "/.") != 0 &&
        (n < 3 || strcmp(path+n-3, "/..") != 0), "INVALID_ARGUMENT");
    CFStringRef string = CFStringCreateWithCString(NULL, path, kCFStringEncodingUTF8);
    require(string != NULL, "INVALID_ARGUMENT");
    CFRelease(string);
}
static void job_check(const char *job) {
    uuid_t value; char canonical[37];
    require(strlen(job) == 36 && uuid_parse(job, value) == 0, "INVALID_ARGUMENT");
    uuid_unparse_lower(value, canonical);
    require(strcmp(job, canonical) == 0, "INVALID_ARGUMENT");
}
static void generation_check(const struct generation *value, bool optional) {
    if (optional && !value->pid) {
        require(!value->seconds && !value->micros, "INVALID_ARGUMENT");
        return;
    }
    require(value->pid > 0 && value->uid > 0 && value->uid < UINT32_MAX &&
        value->seconds > 0 && value->micros < 1000000, "INVALID_ARGUMENT");
}
static struct request request_read(int fd) {
    char bytes[MAX_REQUEST + 1]; size_t count = 0;
    while (count < sizeof(bytes)) {
        ssize_t got = read(fd, bytes + count, sizeof(bytes) - count);
        if (got < 0 && errno == EINTR) continue;
        require(got >= 0, "UNAVAILABLE");
        if (!got) break;
        count += (size_t)got;
    }
    require(count > 0 && count <= MAX_REQUEST && bytes[count-1] == '\n', "INVALID_ARGUMENT");
    require(memchr(bytes, 0, count) == NULL, "INVALID_ARGUMENT");
    bytes[count] = 0;
    char *fields[15], *cursor = bytes;
    for (size_t i = 0; i < 15; ++i) {
        fields[i] = cursor;
        char *newline = strchr(cursor, '\n');
        require(newline != NULL, "INVALID_ARGUMENT");
        *newline = 0; cursor = newline + 1;
    }
    require(!*cursor && strcmp(fields[0], "1") == 0, "INVALID_ARGUMENT");
    struct request request = {0};
    job_check(fields[1]); text_copy(request.job, sizeof(request.job), fields[1]);
    require(strcmp(fields[2], "MACHINE") == 0 || strcmp(fields[2], "USER_LOCAL") == 0, "INVALID_ARGUMENT");
    request.machine = strcmp(fields[2], "MACHINE") == 0;
    uint64_t pid = number(fields[3], false), uid = number(fields[4], false), frontend = number(fields[7], true);
    require(pid <= INT_MAX && frontend <= INT_MAX && uid < UINT32_MAX, "INVALID_ARGUMENT");
    request.owner = (struct generation){(pid_t)pid, (uid_t)uid, number(fields[5], false), number(fields[6], true)};
    request.frontend = (struct generation){(pid_t)frontend, (uid_t)uid, number(fields[8], true), number(fields[9], true)};
    generation_check(&request.owner, false); generation_check(&request.frontend, true);
    require(!request.frontend.pid || request.frontend.pid != request.owner.pid, "INVALID_ARGUMENT");
    request.package_size = number(fields[10], false);
    require(strlen(fields[11]) == 64, "INVALID_ARGUMENT");
    for (const char *p = fields[11]; *p; ++p) require((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f'), "INVALID_ARGUMENT");
    text_copy(request.sha256, sizeof(request.sha256), fields[11]);
    path_check(fields[12]); path_check(fields[13]); path_check(fields[14]);
    text_copy(request.package, sizeof(request.package), fields[12]);
    text_copy(request.launcher, sizeof(request.launcher), fields[13]);
    text_copy(request.workspace, sizeof(request.workspace), fields[14]);
    const char *suffix = "/Contents/MacOS/vpn-control";
    size_t length = strlen(request.launcher), tail = strlen(suffix);
    require(length > tail + 4 && strcmp(request.launcher + length - tail, suffix) == 0, "INVALID_ARGUMENT");
    text_copy(request.bundle, sizeof(request.bundle), request.launcher);
    request.bundle[length-tail] = 0;
    require(strcmp(request.bundle + strlen(request.bundle) - 4, ".app") == 0, "INVALID_ARGUMENT");
    return request;
}

static bool generation_snapshot(pid_t pid, struct proc_bsdinfo *info) {
    memset(info, 0, sizeof(*info));
    int size = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, info, sizeof(*info));
    if (size == 0 && (errno == ESRCH || errno == ENOENT)) return false;
    require(size == (int)sizeof(*info), "OUTCOME_UNKNOWN");
    return true;
}
/* False means the exact generation exited, not permission failure or a partial native snapshot. */
static bool generation_alive(const struct generation *expected, const char *image) {
    if (!expected->pid) return false;
    struct proc_bsdinfo before, after;
    if (!generation_snapshot(expected->pid, &before)) return false;
    if (before.pbi_start_tvsec != expected->seconds || before.pbi_start_tvusec != expected->micros) return false;
    require(before.pbi_pid == (uint32_t)expected->pid && before.pbi_uid == expected->uid &&
        before.pbi_ruid == expected->uid && before.pbi_svuid == expected->uid, "CONFLICT");
    char actual[PROC_PIDPATHINFO_MAXSIZE];
    require(proc_pidpath(expected->pid, actual, sizeof(actual)) > 0, "OUTCOME_UNKNOWN");
    require(strcmp(actual, image) == 0, "CONFLICT");
    if (!generation_snapshot(expected->pid, &after)) return false;
    require(after.pbi_start_tvsec == before.pbi_start_tvsec && after.pbi_start_tvusec == before.pbi_start_tvusec &&
        after.pbi_uid == before.pbi_uid && after.pbi_ruid == before.pbi_ruid && after.pbi_svuid == before.pbi_svuid, "CONFLICT");
    return true;
}
static void acl_check(int fd, bool ancestry) {
    errno = 0;
    acl_t acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED);
    if (!acl) { require(errno == ENOENT, "UNAVAILABLE"); return; }
    require(acl_valid(acl) == 0, "INVALID_ARGUMENT");
    acl_entry_t entry; int selector = ACL_FIRST_ENTRY; size_t count = 0;
    while (true) {
        errno = 0;
        int result = acl_get_entry(acl, selector, &entry);
        if (result == -1 && errno == EINVAL) break;
        require(result == 0 && ancestry && ++count <= 4096, "INVALID_ARGUMENT");
        acl_tag_t tag;
        require(acl_get_tag_type(entry, &tag) == 0 && tag == ACL_EXTENDED_DENY, "INVALID_ARGUMENT");
        selector = ACL_NEXT_ENTRY;
    }
    require(acl_free(acl) == 0, "UNAVAILABLE");
}
static struct stat inspect(int fd, uid_t owner, bool directory, bool ancestry, bool private) {
    struct stat info;
    require(fstat(fd, &info) == 0, "UNAVAILABLE");
    require(directory ? S_ISDIR(info.st_mode) : S_ISREG(info.st_mode), "INVALID_ARGUMENT");
    require(info.st_uid == owner || (ancestry && info.st_uid == 0), "INVALID_ARGUMENT");
    bool administrative = false;
    if (ancestry && info.st_uid == 0 && !(info.st_mode & S_IWOTH)) {
        struct group group, *result = NULL; char buffer[65536];
        administrative = getgrnam_r("admin", &group, buffer, sizeof(buffer), &result) == 0 &&
            result && strcmp(result->gr_name, "admin") == 0 && info.st_gid == result->gr_gid;
    }
    require(!(info.st_mode & (S_IWGRP|S_IWOTH)) || administrative ||
        (ancestry && info.st_uid == 0 && (info.st_mode & S_ISVTX)), "INVALID_ARGUMENT");
    if (private && !ancestry) require(!(info.st_mode & 077), "INVALID_ARGUMENT");
    require(directory || info.st_nlink == 1, "INVALID_ARGUMENT");
    acl_check(fd, ancestry);
    return info;
}
static int directory_open(const char *path, uid_t owner, bool private, bool final_ancestry, struct pins *pins) {
    path_check(path);
    int fd = open("/", O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    retain(pins, fd); inspect(fd, owner, true, true, false);
    char components[PATH_MAX]; text_copy(components, sizeof(components), path + 1);
    char *cursor = components;
    while (cursor && *cursor) {
        char *next = strchr(cursor, '/');
        if (next) *next++ = 0;
        fd = openat(fd, cursor, O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
        retain(pins, fd); inspect(fd, owner, true, next != NULL || final_ancestry, private);
        cursor = next;
    }
    char actual[PATH_MAX];
    require(fcntl(fd, F_GETPATH, actual) == 0 && strcmp(actual, path) == 0, "CONFLICT");
    return fd;
}

static void join(char *out, size_t size, const char *parent, const char *leaf) {
    require(leaf && *leaf && !strchr(leaf, '/') && strcmp(leaf, ".") && strcmp(leaf, ".."), "INVALID_ARGUMENT");
    int count = snprintf(out, size, "%s/%s", parent, leaf);
    require(count > 0 && (size_t)count < size, "INVALID_ARGUMENT");
}
static void home_for(uid_t uid, char *out, size_t size) {
    struct passwd password, *result = NULL; char buffer[65536];
    require(getpwuid_r(uid, &password, buffer, sizeof(buffer), &result) == 0 && result && result->pw_uid == uid, "UNAVAILABLE");
    path_check(result->pw_dir); text_copy(out, size, result->pw_dir);
}
static void authority_root(const struct request *request, char *out, size_t size) {
    if (request->machine) text_copy(out, size, "/Library/Application Support/vpn-control-install-jobs");
    else {
        char home[PATH_MAX]; home_for(request->owner.uid, home, sizeof(home));
        int count = snprintf(out, size, "%s/Library/Application Support/vpn-control-install-jobs", home);
        require(count > 0 && (size_t)count < size, "INVALID_ARGUMENT");
    }
}
static void input_path(uid_t uid, const char *job, char *out, size_t size) {
    char home[PATH_MAX]; home_for(uid, home, sizeof(home));
    int count = snprintf(out, size, "%s/Library/Application Support/vpn-control-install-inputs/%s", home, job);
    require(count > 0 && (size_t)count < size, "INVALID_ARGUMENT");
}
static void write_all(int fd, const void *bytes, size_t size) {
    const char *cursor = bytes;
    while (size) {
        ssize_t written = write(fd, cursor, size);
        if (written < 0 && errno == EINTR) continue;
        require(written > 0, "PERSISTENCE_FAILED");
        cursor += written; size -= (size_t)written;
    }
}
struct receipt_writer { int directory, cancel; char job[37]; unsigned long long sequence; bool terminal, local; };
static void publish(struct receipt_writer *writer, const char *phase, const char *code) {
    require(!writer->terminal, "CONFLICT");
    uuid_t uuid; char id[37], temporary[64]; uuid_generate_random(uuid); uuid_unparse_lower(uuid, id);
    snprintf(temporary, sizeof(temporary), "status-%s.tmp", id);
    int fd = openat(writer->directory, temporary, O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC, writer->local ? 0600 : 0644);
    require(fd >= 0, "PERSISTENCE_FAILED");
    require(fchmod(fd, writer->local ? 0600 : 0644) == 0, "PERSISTENCE_FAILED");
    char bytes[4096];
    int size = snprintf(bytes, sizeof(bytes), "{\"version\":1,\"jobId\":\"%s\",\"sequence\":%llu,\"phase\":\"%s\",\"code\":\"%s\"}",
        writer->job, writer->sequence++, phase, code);
    require(size > 0 && (size_t)size < sizeof(bytes), "PERSISTENCE_FAILED");
    write_all(fd, bytes, (size_t)size);
    require(fsync(fd) == 0 && close(fd) == 0, "PERSISTENCE_FAILED");
    require(renameat(writer->directory, temporary, writer->directory, "status.json") == 0 && fsync(writer->directory) == 0, "PERSISTENCE_FAILED");
    writer->terminal = !strcmp(phase, "SUCCEEDED") || !strcmp(phase, "FAILED") || !strcmp(phase, "CANCELLED");
}
static bool cancelled(const struct receipt_writer *writer) {
    unsigned char bytes[2]; ssize_t count = pread(writer->cancel, bytes, sizeof(bytes), 0);
    require(count == 1 && bytes[0] <= 1, "INVALID_ARGUMENT");
    return bytes[0] == 1;
}
static int root_create(const struct request *request, struct pins *pins) {
    char root[PATH_MAX], parent[PATH_MAX]; authority_root(request, root, sizeof(root));
    text_copy(parent, sizeof(parent), root); *strrchr(parent, '/') = 0;
    uid_t uid = request->machine ? 0 : request->owner.uid;
    int directory = directory_open(parent, uid, false, true, pins);
    mode_t mode = request->machine ? 0755 : 0700;
    int created = mkdirat(directory, "vpn-control-install-jobs", mode);
    require(created == 0 || errno == EEXIST, "PERSISTENCE_FAILED");
    int fd = openat(directory, "vpn-control-install-jobs", O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    retain(pins, fd);
    if (!created) require(fchmod(fd, mode) == 0, "PERSISTENCE_FAILED");
    inspect(fd, uid, true, false, !request->machine);
    char actual[PATH_MAX]; require(fcntl(fd, F_GETPATH, actual) == 0 && !strcmp(actual, root), "CONFLICT");
    return fd;
}
static struct receipt_writer job_create(int root, const struct request *request, struct pins *pins) {
    mode_t mode = request->machine ? 0755 : 0700;
    require(mkdirat(root, request->job, mode) == 0, "CONFLICT");
    int fd = openat(root, request->job, O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    retain(pins, fd); require(fchmod(fd, mode) == 0, "PERSISTENCE_FAILED");
    inspect(fd, request->machine ? 0 : request->owner.uid, true, false, !request->machine);
    int cancel = openat(fd, "cancel", O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC, 0600);
    retain(pins, cancel);
    require(fchmod(cancel, 0600) == 0, "PERSISTENCE_FAILED");
    if (request->machine) require(fchown(cancel, request->owner.uid, (gid_t)-1) == 0, "PERSISTENCE_FAILED");
    inspect(cancel, request->owner.uid, false, false, true);
    const unsigned char zero = 0; write_all(cancel, &zero, 1); require(fsync(cancel) == 0, "PERSISTENCE_FAILED");
    struct receipt_writer writer = {.directory=fd, .cancel=cancel, .sequence=0, .terminal=false, .local=!request->machine};
    text_copy(writer.job, sizeof(writer.job), request->job);
    publish(&writer, "PREPARING", "OK");
    return writer;
}
static void digest_hex(const unsigned char *digest, size_t length, char *out) {
    const char *hex = "0123456789abcdef";
    for (size_t i = 0; i < length; ++i) { out[2*i] = hex[digest[i] >> 4]; out[2*i+1] = hex[digest[i] & 15]; }
    out[2*length] = 0;
}
static int gate_open(int root, const struct request *request, struct pins *pins) {
    unsigned char hash[CC_SHA256_DIGEST_LENGTH]; char id[33], name[41];
    CC_SHA256(request->bundle, (CC_LONG)strlen(request->bundle), hash); digest_hex(hash, 16, id);
    mode_t mode = request->machine ? 0644 : 0600;
    // Darwin fcntl and flock locks conflict even for different byte ranges.
    // Reserve a separate protected inode so pending status/cancel readers can
    // retain the admission gate while this coordinator waits for handoff.
    snprintf(name, sizeof(name), "reserve-%s", id);
    int reservation = openat(root, name, O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC, mode);
    if (reservation >= 0) {
        require(fchmod(reservation, mode) == 0 && fsync(reservation) == 0, "PERSISTENCE_FAILED");
    } else {
        require(errno == EEXIST, "UNAVAILABLE");
        reservation = openat(root, name, O_RDWR|O_NOFOLLOW|O_CLOEXEC);
    }
    retain(pins, reservation);
    struct stat reservation_info = inspect(reservation, request->machine ? 0 : request->owner.uid,
        false, false, !request->machine);
    require(reservation_info.st_size == 0, "INVALID_ARGUMENT");
    if (flock(reservation, LOCK_EX|LOCK_NB) != 0) fail(errno == EWOULDBLOCK ? "BUSY" : "UNAVAILABLE");
    snprintf(name, sizeof(name), "gate-%s", id);
    int fd = openat(root, name, O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC, mode);
    if (fd >= 0) {
        require(fchmod(fd, mode) == 0, "PERSISTENCE_FAILED");
        unsigned char bytes[17] = {0}; write_all(fd, bytes, sizeof(bytes)); require(fsync(fd) == 0, "PERSISTENCE_FAILED");
    } else {
        require(errno == EEXIST, "UNAVAILABLE");
        fd = openat(root, name, O_RDWR|O_NOFOLLOW|O_CLOEXEC);
    }
    retain(pins, fd);
    struct stat info = inspect(fd, request->machine ? 0 : request->owner.uid, false, false, !request->machine);
    unsigned char bytes[18]; ssize_t size = pread(fd, bytes, sizeof(bytes), 0);
    require(info.st_size == 17 && size == 17, "INVALID_ARGUMENT");
    for (size_t i = 0; i < 17; ++i) require(bytes[i] == 0, "BUSY");
    return fd;
}
static void gate_pending(int fd, bool pending) {
    unsigned char value = pending ? 1 : 0;
    require(pwrite(fd, &value, 1, 8) == 1 && fsync(fd) == 0, "PERSISTENCE_FAILED");
}

static void cancellation_finish(struct receipt_writer *writer, int gate);
static void package_capture(int input, const struct request *request, struct receipt_writer *writer, int gate) {
    int source = openat(input, "package.dmg", O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    require(source >= 0, "UNAVAILABLE");
    struct stat before = inspect(source, request->owner.uid, false, false, true);
    require(before.st_size > 0 && (uint64_t)before.st_size == request->package_size, "INVALID_ARGUMENT");
    int target = openat(writer->directory, "package.dmg", O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC, 0600);
    require(target >= 0 && fchmod(target, 0600) == 0, "PERSISTENCE_FAILED");
    CC_SHA256_CTX digest; CC_SHA256_Init(&digest);
    unsigned char bytes[65536]; uint64_t total = 0;
    while (true) {
        if (cancelled(writer)) { close(source); close(target); cancellation_finish(writer, gate); }
        ssize_t count = read(source, bytes, sizeof(bytes));
        if (count < 0 && errno == EINTR) continue;
        require(count >= 0, "UNAVAILABLE");
        if (!count) break;
        require((uint64_t)count <= request->package_size - total, "INVALID_ARGUMENT");
        write_all(target, bytes, (size_t)count); CC_SHA256_Update(&digest, bytes, (CC_LONG)count); total += (uint64_t)count;
    }
    unsigned char hash[CC_SHA256_DIGEST_LENGTH]; char hex[65]; CC_SHA256_Final(hash, &digest); digest_hex(hash, sizeof(hash), hex);
    struct stat after;
    require(fstat(source, &after) == 0 && after.st_dev == before.st_dev && after.st_ino == before.st_ino &&
        after.st_size == before.st_size && after.st_nlink == 1 && total == request->package_size &&
        !strcmp(hex, request->sha256), "INVALID_ARGUMENT");
    require(fsync(target) == 0, "PERSISTENCE_FAILED"); close(source); close(target);
}
static uint64_t monotonic_seconds(void) {
    struct timespec now; require(clock_gettime(CLOCK_MONOTONIC, &now) == 0, "UNAVAILABLE"); return (uint64_t)now.tv_sec;
}
static int command(char *const argv[], unsigned char *output, size_t capacity, size_t *output_size) {
    int pipefd[2]; require(pipe(pipefd) == 0, "UNAVAILABLE");
    pid_t child = fork(); require(child >= 0, "UNAVAILABLE");
    if (!child) {
        int empty = open("/dev/null", O_RDWR);
        if (empty < 0 || dup2(empty, STDIN_FILENO) < 0 || dup2(pipefd[1], STDOUT_FILENO) < 0 || dup2(empty, STDERR_FILENO) < 0) _exit(126);
        close(empty); close(pipefd[0]); close(pipefd[1]);
        char *const environment[] = {"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=en_US.UTF-8", NULL};
        execve(argv[0], argv, environment); _exit(127);
    }
    close(pipefd[1]); require(fcntl(pipefd[0], F_SETFL, O_NONBLOCK) == 0, "UNAVAILABLE");
    size_t count = 0; int status = 0; bool exited = false, eof = false; uint64_t deadline = monotonic_seconds() + 180;
    while (!exited || !eof) {
        if (monotonic_seconds() >= deadline) {
            kill(child, SIGTERM); close(pipefd[0]); fail("OUTCOME_UNKNOWN");
        }
        unsigned char bytes[8192]; ssize_t got = read(pipefd[0], bytes, sizeof(bytes));
        if (got > 0) {
            require((size_t)got <= capacity - count, "INVALID_ARGUMENT");
            if (output) memcpy(output + count, bytes, (size_t)got);
            count += (size_t)got;
        } else if (!got) eof = true;
        else require(errno == EAGAIN || errno == EINTR, "UNAVAILABLE");
        if (!exited) {
            pid_t waited = waitpid(child, &status, WNOHANG);
            require(waited >= 0 || errno == EINTR, "UNAVAILABLE"); exited = waited == child;
        }
        if (!exited || !eof) { struct pollfd descriptor = {.fd=pipefd[0], .events=POLLIN}; poll(&descriptor, 1, 50); }
    }
    close(pipefd[0]); if (output_size) *output_size = count;
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128;
}
static CFPropertyListRef plist_read(const unsigned char *bytes, size_t size) {
    CFDataRef data = CFDataCreate(NULL, bytes, (CFIndex)size); require(data != NULL, "UNAVAILABLE");
    CFPropertyListRef plist = CFPropertyListCreateWithData(NULL, data, kCFPropertyListImmutable, NULL, NULL);
    CFRelease(data); require(plist && CFGetTypeID(plist) == CFDictionaryGetTypeID(), "INVALID_ARGUMENT");
    return plist;
}
static bool cf_string_equals(CFTypeRef value, const char *expected) {
    if (!value || CFGetTypeID(value) != CFStringGetTypeID()) return false;
    char bytes[PATH_MAX]; return CFStringGetCString(value, bytes, sizeof(bytes), kCFStringEncodingUTF8) && !strcmp(bytes, expected);
}
static void mount_package(const char *package, const char *mountpoint) {
    unsigned char *bytes = malloc(1024*1024); require(bytes != NULL, "UNAVAILABLE"); size_t size = 0;
    char *const argv[] = {"/usr/bin/hdiutil", "attach", "-readonly", "-nobrowse", "-owners", "on", "-mountpoint",
        (char *)mountpoint, "-plist", (char *)package, NULL};
    require(command(argv, bytes, 1024*1024, &size) == 0, "RUNTIME_FAILED");
    CFPropertyListRef plist = plist_read(bytes, size); free(bytes);
    CFTypeRef entities = CFDictionaryGetValue(plist, CFSTR("system-entities"));
    require(entities && CFGetTypeID(entities) == CFArrayGetTypeID() && CFArrayGetCount(entities) <= 128, "INVALID_ARGUMENT");
    size_t mounted = 0;
    for (CFIndex i = 0; i < CFArrayGetCount(entities); ++i) {
        CFTypeRef entity = CFArrayGetValueAtIndex(entities, i);
        require(CFGetTypeID(entity) == CFDictionaryGetTypeID(), "INVALID_ARGUMENT");
        CFTypeRef path = CFDictionaryGetValue(entity, CFSTR("mount-point"));
        if (path) { require(cf_string_equals(path, mountpoint), "INVALID_ARGUMENT"); mounted++; }
    }
    require(mounted == 1, "INVALID_ARGUMENT"); CFRelease(plist);
    struct statfs filesystem;
    require(statfs(mountpoint, &filesystem) == 0 && (filesystem.f_flags & MNT_RDONLY), "INVALID_ARGUMENT");
}

static void tree_verify(const char *root, const char *path, size_t depth, size_t *entries, bool normalize, uid_t owner) {
    require(depth <= 128 && ++*entries <= 200000, "INVALID_ARGUMENT");
    struct stat before; require(lstat(path, &before) == 0, "UNAVAILABLE");
    if (S_ISLNK(before.st_mode)) {
        char actual[PATH_MAX];
        require(realpath(path, actual) != NULL && !strncmp(actual, root, strlen(root)) &&
            (actual[strlen(root)] == '/' || actual[strlen(root)] == 0), "INVALID_ARGUMENT");
        return; // Preserve legitimate internal bundle links; never traverse them during copy/cleanup.
    }
    require((S_ISDIR(before.st_mode) || S_ISREG(before.st_mode)) && !(before.st_mode & (S_ISUID|S_ISGID|S_IWGRP|S_IWOTH)), "INVALID_ARGUMENT");
    require(S_ISDIR(before.st_mode) || before.st_nlink == 1, "INVALID_ARGUMENT");
    int fd = open(path, O_RDONLY|O_NOFOLLOW|O_CLOEXEC|(S_ISDIR(before.st_mode) ? O_DIRECTORY : 0));
    require(fd >= 0, "UNAVAILABLE");
    struct stat actual; require(fstat(fd, &actual) == 0 && actual.st_dev == before.st_dev && actual.st_ino == before.st_ino, "CONFLICT");
    acl_check(fd, false);
    if (normalize) {
        require(fchown(fd, owner, (gid_t)-1) == 0, "PERSISTENCE_FAILED");
        require(fchmod(fd, before.st_mode & 0777) == 0, "PERSISTENCE_FAILED");
        require(fsync(fd) == 0, "PERSISTENCE_FAILED");
    }
    if (S_ISDIR(before.st_mode)) {
        DIR *directory = fdopendir(fd); require(directory != NULL, "UNAVAILABLE");
        struct dirent *entry;
        while (true) {
            errno = 0; entry = readdir(directory);
            if (!entry) { require(errno == 0, "UNAVAILABLE"); break; }
            if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
            char child[PATH_MAX]; join(child, sizeof(child), path, entry->d_name);
            tree_verify(root, child, depth+1, entries, normalize, owner);
        }
        require(closedir(directory) == 0, "UNAVAILABLE");
    } else close(fd);
}
static CFPropertyListRef bundle_info(const char *bundle) {
    char path[PATH_MAX]; int count = snprintf(path, sizeof(path), "%s/Contents/Info.plist", bundle);
    require(count > 0 && (size_t)count < sizeof(path), "INVALID_ARGUMENT");
    int fd = open(path, O_RDONLY|O_NOFOLLOW|O_CLOEXEC); require(fd >= 0, "UNAVAILABLE");
    struct stat info; require(fstat(fd, &info) == 0 && S_ISREG(info.st_mode) && info.st_nlink == 1 &&
        info.st_size > 0 && info.st_size <= 1024*1024, "INVALID_ARGUMENT");
    unsigned char *bytes = malloc((size_t)info.st_size); require(bytes != NULL, "UNAVAILABLE");
    size_t total = 0;
    while (total < (size_t)info.st_size) {
        ssize_t count = read(fd, bytes+total, (size_t)info.st_size-total);
        if (count < 0 && errno == EINTR) continue;
        require(count > 0, "UNAVAILABLE"); total += (size_t)count;
    }
    close(fd); CFPropertyListRef plist = plist_read(bytes, total); free(bytes);
    require(cf_string_equals(CFDictionaryGetValue(plist, CFSTR("CFBundleExecutable")), "vpn-control") &&
        cf_string_equals(CFDictionaryGetValue(plist, CFSTR("CFBundlePackageType")), "APPL"), "INVALID_ARGUMENT");
    CFTypeRef identity = CFDictionaryGetValue(plist, CFSTR("CFBundleIdentifier"));
    require(identity && CFGetTypeID(identity) == CFStringGetTypeID() && CFStringGetLength(identity) > 0, "INVALID_ARGUMENT");
    return plist;
}
static bool same_inode(int fd, int parent, const char *name) {
    struct stat held, named;
    return fstat(fd, &held) == 0 && fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) == 0 &&
        held.st_dev == named.st_dev && held.st_ino == named.st_ino;
}
/* Best-effort after a terminal success only. Never follows a link or targets a guessed sibling. */
static bool erase_directory_contents(int fd, size_t depth, size_t *entries) {
    if (depth > 128 || ++*entries > 200000) return false;
    if (geteuid() == 0 && (fchown(fd, 0, (gid_t)-1) != 0 || fchmod(fd, 0700) != 0)) return false;
    int copy = dup(fd); if (copy < 0) return false;
    DIR *directory = fdopendir(copy); if (!directory) { close(copy); return false; }
    bool good = true;
    while (true) {
        errno = 0; struct dirent *entry = readdir(directory);
        if (!entry) { if (errno) good = false; break; }
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        struct stat named, opened;
        if (fstatat(fd, entry->d_name, &named, AT_SYMLINK_NOFOLLOW) != 0) { good = false; break; }
        if (S_ISDIR(named.st_mode)) {
            int child = openat(fd, entry->d_name, O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
            if (child < 0) { good = false; break; }
            bool removed = fstat(child, &opened) == 0 && opened.st_dev == named.st_dev && opened.st_ino == named.st_ino &&
                erase_directory_contents(child, depth+1, entries) && same_inode(child, fd, entry->d_name) &&
                unlinkat(fd, entry->d_name, AT_REMOVEDIR) == 0;
            close(child); if (!removed) { good = false; break; }
        } else {
            if (++*entries > 200000 || unlinkat(fd, entry->d_name, 0) != 0) { good = false; break; }
        }
    }
    if (closedir(directory) != 0) good = false;
    return good;
}
static bool receipt_read(int job, uid_t owner, bool local, const char *job_id, unsigned long long *sequence, char phase[32]) {
    int fd = openat(job, "status.json", O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if (fd < 0 && errno == ENOENT) return false;
    require(fd >= 0, "UNAVAILABLE"); inspect(fd, owner, false, false, local);
    char bytes[4097]; ssize_t count = pread(fd, bytes, sizeof(bytes)-1, 0); close(fd);
    require(count > 0 && count < (ssize_t)sizeof(bytes)-1, "INVALID_ARGUMENT"); bytes[count] = 0;
    char read_job[37], read_phase[32], code[32], canonical[4097]; unsigned long long read_sequence; int end = 0;
    int fields = sscanf(bytes, "{\"version\":1,\"jobId\":\"%36[a-f0-9-]\",\"sequence\":%llu,\"phase\":\"%31[A-Z_]\",\"code\":\"%31[A-Z_]\"}%n",
        read_job, &read_sequence, read_phase, code, &end);
    require(fields == 4 && end == count && !strcmp(read_job, job_id), "INVALID_ARGUMENT");
    snprintf(canonical, sizeof(canonical), "{\"version\":1,\"jobId\":\"%s\",\"sequence\":%llu,\"phase\":\"%s\",\"code\":\"%s\"}",
        read_job, read_sequence, read_phase, code);
    require(!strcmp(canonical, bytes) && read_sequence >= *sequence, "INVALID_ARGUMENT");
    require(!strcmp(read_phase, "PREPARING") || !strcmp(read_phase, "AUTHORIZED") || !strcmp(read_phase, "WAITING_FOR_EXIT") ||
        !strcmp(read_phase, "INSTALLING") || !strcmp(read_phase, "SUCCEEDED") || !strcmp(read_phase, "FAILED") || !strcmp(read_phase, "CANCELLED"), "INVALID_ARGUMENT");
    if (!strcmp(read_phase, "SUCCEEDED")) require(!strcmp(code, "OK"), "INVALID_ARGUMENT");
    *sequence = read_sequence; text_copy(phase, 32, read_phase); return true;
}
static int open_existing_job(const struct request *request, struct pins *pins) {
    char root[PATH_MAX]; authority_root(request, root, sizeof(root));
    uid_t uid = request->machine ? 0 : request->owner.uid;
    int parent = directory_open(root, uid, !request->machine, false, pins);
    int job = openat(parent, request->job, O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    retain(pins, job); inspect(job, uid, true, false, !request->machine); return job;
}
static void relaunch(const struct request *request) {
    if (request->frontend.pid)
        execl(request->launcher, request->launcher, "--state-dir", request->workspace, (char *)NULL);
    else
        execl(request->launcher, request->launcher, "--state-dir", request->workspace, "serve", (char *)NULL);
    fail("RUNTIME_FAILED");
}
static void watcher(const struct request *request) {
    require(getuid() == request->owner.uid && geteuid() == request->owner.uid, "PRIVILEGES_REQUIRED");
    require(install_watcher_group() == 0, "UNAVAILABLE");
    require(generation_alive(&request->owner, request->launcher), "CONFLICT");
    if (request->frontend.pid) require(generation_alive(&request->frontend, request->launcher), "CONFLICT");
    struct proc_bsdinfo self; require(generation_snapshot(getpid(), &self), "UNAVAILABLE");
    printf("%s\n%d\n%llu\n%llu\n", request->job, getpid(),
        (unsigned long long)self.pbi_start_tvsec, (unsigned long long)self.pbi_start_tvusec); fflush(stdout);
    uint64_t deadline = monotonic_seconds()+3600;
    char job_path[PATH_MAX], root[PATH_MAX]; authority_root(request, root, sizeof(root)); join(job_path, sizeof(job_path), root, request->job);
    while (access(job_path, F_OK) != 0) {
        require(errno == ENOENT && monotonic_seconds() < deadline, "OUTCOME_UNKNOWN");
        usleep(100000);
    }
    struct pins pins = {0}; int job = open_existing_job(request, &pins); unsigned long long sequence = 0; char phase[32];
    while (monotonic_seconds() < deadline) {
        if (receipt_read(job, request->machine ? 0 : request->owner.uid, !request->machine, request->job, &sequence, phase)) {
            if (!strcmp(phase, "CANCELLED") || !strcmp(phase, "FAILED")) { release(&pins); return; }
            if (!strcmp(phase, "SUCCEEDED")) {
                require(!generation_alive(&request->owner, request->launcher) &&
                    !generation_alive(&request->frontend, request->launcher), "CONFLICT");
                // This process never elevated or changed UID, environment, audit or login session.
                // Launch only after an authoritative terminal receipt and all exact old generations exited.
                release(&pins);
                relaunch(request);
            }
        }
        usleep(100000);
    }
    fail("OUTCOME_UNKNOWN");
}

struct transaction {
    struct receipt_writer *writer;
    int parent, old_bundle, candidate, gate, executable;
    char target[NAME_MAX+1], stage[NAME_MAX+1], backup[NAME_MAX+1];
    unsigned int renamed;
};
static struct transaction active = {.parent=-1, .old_bundle=-1, .candidate=-1, .gate=-1, .executable=-1};
static void transaction_failed(const char *code) {
    bool restored = true;
    if (active.renamed == 2) {
        restored = same_inode(active.candidate, active.parent, active.target) &&
            renameatx_np(active.parent, active.target, active.parent, active.stage, RENAME_EXCL) == 0;
        if (restored) active.renamed = 1;
    }
    if (active.renamed == 1 && restored) {
        restored = same_inode(active.old_bundle, active.parent, active.backup) &&
            renameatx_np(active.parent, active.backup, active.parent, active.target, RENAME_EXCL) == 0 &&
            fsync(active.parent) == 0 && same_inode(active.old_bundle, active.parent, active.target);
        if (restored) active.renamed = 0;
    }
    // Unknown mutation/rollback never produces a terminal receipt or clears admission.
    // Preserve the exact UUID backup and pending job for protected reconciliation.
    if (!restored || !strcmp(code, "OUTCOME_UNKNOWN")) return;
    if (active.gate >= 0) { gate_pending(active.gate, false); flock(active.gate, LOCK_UN); }
    if (active.executable >= 0) flock(active.executable, LOCK_UN);
    if (active.writer && !active.writer->terminal) publish(active.writer, "FAILED", code);
}
static bool committed(int input, const char *job, uid_t uid) {
    int fd = openat(input, "commit", O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if (fd < 0 && errno == ENOENT) return false;
    require(fd >= 0, "UNAVAILABLE"); inspect(fd, uid, false, false, true);
    char bytes[38]; ssize_t count = pread(fd, bytes, sizeof(bytes), 0); close(fd);
    require(count == 37 && bytes[36] == '\n' && !memcmp(bytes, job, 36), "INVALID_ARGUMENT"); return true;
}
static void cancellation_finish(struct receipt_writer *writer, int gate) {
    gate_pending(gate, false); flock(gate, LOCK_UN);
    if (active.executable >= 0) flock(active.executable, LOCK_UN);
    publish(writer, "CANCELLED", "CANCELLED"); exit(0);
}
static int pin_executable(const struct request *request, struct pins *pins) {
    char parent[PATH_MAX]; text_copy(parent, sizeof(parent), request->launcher); *strrchr(parent, '/') = 0;
    int directory = directory_open(parent, request->owner.uid, false, true, pins);
    int executable = openat(directory, "vpn-control", O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    retain(pins, executable);
    struct stat info; require(fstat(executable, &info) == 0, "UNAVAILABLE");
    require(info.st_uid == 0 || info.st_uid == request->owner.uid, "INVALID_ARGUMENT");
    inspect(executable, info.st_uid, false, false, false);
    require(info.st_mode & 0111, "INVALID_ARGUMENT");
    require(!(info.st_mode & (S_ISUID|S_ISGID)), "INVALID_ARGUMENT");
    char actual[PATH_MAX]; require(fcntl(executable, F_GETPATH, actual) == 0 && !strcmp(actual, request->launcher), "CONFLICT");
    return executable;
}
static struct generation captured_watcher(int input, const struct request *request, char image[PATH_MAX]) {
    int fd = openat(input, "watcher", O_RDONLY|O_NOFOLLOW|O_CLOEXEC); require(fd >= 0, "UNAVAILABLE");
    inspect(fd, request->owner.uid, false, false, true);
    char bytes[257], job[37], canonical[257]; ssize_t size = pread(fd, bytes, sizeof(bytes)-1, 0); close(fd);
    require(size > 0 && size < (ssize_t)sizeof(bytes)-1, "INVALID_ARGUMENT"); bytes[size] = 0;
    unsigned long long pid, seconds, micros; int end = 0;
    require(sscanf(bytes, "%36[a-f0-9-]\n%llu\n%llu\n%llu\n%n", job, &pid, &seconds, &micros, &end) == 4 &&
        end == size && pid > 0 && pid <= INT_MAX && !strcmp(job, request->job), "INVALID_ARGUMENT");
    snprintf(canonical, sizeof(canonical), "%s\n%llu\n%llu\n%llu\n", job, pid, seconds, micros);
    require(!strcmp(bytes, canonical), "INVALID_ARGUMENT");
    struct generation watcher = {(pid_t)pid, request->owner.uid, seconds, micros}; generation_check(&watcher, false);
    char input_directory[PATH_MAX]; require(fcntl(input, F_GETPATH, input_directory) == 0, "UNAVAILABLE");
    join(image, PATH_MAX, input_directory, "vpn-control-install-worker");
    require(generation_alive(&watcher, image), "CONFLICT"); return watcher;
}
static void coordinator(struct request *request, int input) {
    uid_t authority = request->machine ? 0 : request->owner.uid;
    require(geteuid() == authority && getuid() == authority, "PRIVILEGES_REQUIRED");
    require(install_watcher_group() == 0, "UNAVAILABLE");
    require(generation_alive(&request->owner, request->launcher), "CONFLICT");
    if (request->frontend.pid) require(generation_alive(&request->frontend, request->launcher), "CONFLICT");
    char watcher_image[PATH_MAX]; struct generation original_watcher = captured_watcher(input, request, watcher_image);
    struct pins pins = {0};
    int root = root_create(request, &pins);
    struct receipt_writer writer = job_create(root, request, &pins);
    active.writer = &writer; failure_handler = transaction_failed;
    int gate = gate_open(root, request, &pins); active.gate = gate;
    gate_pending(gate, true);
    int executable = pin_executable(request, &pins); active.executable = executable;
    char parent_path[PATH_MAX]; text_copy(parent_path, sizeof(parent_path), request->bundle);
    char *target = strrchr(parent_path, '/'); require(target && target[1], "INVALID_ARGUMENT");
    text_copy(active.target, sizeof(active.target), target+1); *target = 0;
    active.parent = directory_open(parent_path, authority, false, true, &pins);
    active.old_bundle = openat(active.parent, active.target, O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    retain(&pins, active.old_bundle);
    struct stat old_stat; require(fstat(active.old_bundle, &old_stat) == 0 &&
        (old_stat.st_uid == 0 || old_stat.st_uid == request->owner.uid), "INVALID_ARGUMENT");
    inspect(active.old_bundle, old_stat.st_uid, true, false, false);
    package_capture(input, request, &writer, gate);
    char job_path[PATH_MAX]; require(fcntl(writer.directory, F_GETPATH, job_path) == 0, "UNAVAILABLE");
    char package[PATH_MAX], mountpoint[PATH_MAX], source[PATH_MAX], stage[PATH_MAX];
    join(package, sizeof(package), job_path, "package.dmg"); join(mountpoint, sizeof(mountpoint), job_path, "mount");
    require(mkdirat(writer.directory, "mount", 0700) == 0, "PERSISTENCE_FAILED");
    mount_package(package, mountpoint);
    join(source, sizeof(source), mountpoint, "vpn-control.app");
    size_t entries = 0; tree_verify(source, source, 0, &entries, false, authority);
    CFPropertyListRef incoming = bundle_info(source), old = bundle_info(request->bundle);
    require(CFEqual(CFDictionaryGetValue(incoming, CFSTR("CFBundleIdentifier")),
        CFDictionaryGetValue(old, CFSTR("CFBundleIdentifier"))), "INVALID_ARGUMENT"); CFRelease(incoming); CFRelease(old);
    snprintf(active.stage, sizeof(active.stage), ".vpn-control-stage-%s.app", request->job);
    snprintf(active.backup, sizeof(active.backup), ".vpn-control-backup-%s.app", request->job);
    join(stage, sizeof(stage), parent_path, active.stage);
    require(copyfile(source, stage, NULL, COPYFILE_ALL|COPYFILE_RECURSIVE|COPYFILE_NOFOLLOW|COPYFILE_EXCL) == 0, "PERSISTENCE_FAILED");
    entries = 0; tree_verify(stage, stage, 0, &entries, true, authority);
    active.candidate = openat(active.parent, active.stage, O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    retain(&pins, active.candidate); inspect(active.candidate, authority, true, false, false);
    char *const detach[] = {"/usr/bin/hdiutil", "detach", mountpoint, NULL};
    require(command(detach, NULL, 1024*1024, NULL) == 0, "RUNTIME_FAILED");
    require(fsync(active.parent) == 0, "PERSISTENCE_FAILED");
    if (cancelled(&writer)) cancellation_finish(&writer, gate);
    require(generation_alive(&request->owner, request->launcher), "CONFLICT");
    if (request->frontend.pid) require(generation_alive(&request->frontend, request->launcher), "CONFLICT");
    require(generation_alive(&original_watcher, watcher_image), "CONFLICT");
    publish(&writer, "AUTHORIZED", "OK");
    uint64_t deadline = monotonic_seconds()+600;
    while (!committed(input, request->job, request->owner.uid)) {
        if (cancelled(&writer)) cancellation_finish(&writer, gate);
        require(generation_alive(&request->owner, request->launcher), "CONFLICT");
        require(monotonic_seconds() < deadline, "OUTCOME_UNKNOWN"); usleep(100000);
    }
    publish(&writer, "WAITING_FOR_EXIT", "OK");
    while (generation_alive(&request->owner, request->launcher) || generation_alive(&request->frontend, request->launcher)) {
        if (cancelled(&writer)) cancellation_finish(&writer, gate);
        require(monotonic_seconds() < deadline, "OUTCOME_UNKNOWN"); usleep(100000);
    }
    while (flock(executable, LOCK_EX|LOCK_NB) != 0) {
        require(errno == EWOULDBLOCK, "UNAVAILABLE");
        if (cancelled(&writer)) cancellation_finish(&writer, gate);
        require(monotonic_seconds() < deadline, "OUTCOME_UNKNOWN"); usleep(100000);
    }
    while (flock(gate, LOCK_EX|LOCK_NB) != 0) {
        require(errno == EWOULDBLOCK, "UNAVAILABLE");
        if (cancelled(&writer)) cancellation_finish(&writer, gate);
        require(monotonic_seconds() < deadline, "OUTCOME_UNKNOWN"); usleep(100000);
    }
    if (cancelled(&writer)) cancellation_finish(&writer, gate);
    require(generation_alive(&original_watcher, watcher_image), "CONFLICT");
    require(same_inode(active.old_bundle, active.parent, active.target) &&
        same_inode(active.candidate, active.parent, active.stage), "CONFLICT");
    publish(&writer, "INSTALLING", "OK");
    require(renameatx_np(active.parent, active.target, active.parent, active.backup, RENAME_EXCL) == 0, "PERSISTENCE_FAILED");
    active.renamed = 1;
    require(renameatx_np(active.parent, active.stage, active.parent, active.target, RENAME_EXCL) == 0, "PERSISTENCE_FAILED");
    active.renamed = 2;
    require(fsync(active.parent) == 0 && same_inode(active.candidate, active.parent, active.target), "PERSISTENCE_FAILED");
    gate_pending(gate, false); require(flock(gate, LOCK_UN) == 0 && flock(executable, LOCK_UN) == 0, "UNAVAILABLE");
    publish(&writer, "SUCCEEDED", "OK");
    failure_handler = NULL;
    // Receipt already authoritatively says installed. Cleanup cannot turn a successful
    // replacement into a false rollback or delete an unrelated preexisting backup.
    size_t removed_entries = 0;
    if (same_inode(active.old_bundle, active.parent, active.backup) &&
        erase_directory_contents(active.old_bundle, 0, &removed_entries) &&
        same_inode(active.old_bundle, active.parent, active.backup))
        unlinkat(active.parent, active.backup, AT_REMOVEDIR);
    unlinkat(writer.directory, "package.dmg", 0);
    unlinkat(writer.directory, "mount", AT_REMOVEDIR);
    fsync(writer.directory); fsync(active.parent); release(&pins);
}

/* Called by the unelevated owner only after rereading the exact terminal receipt. */
static void cleanup_input(const char *job_id) {
    uid_t uid = getuid(); require(uid > 0 && uid == geteuid(), "PRIVILEGES_REQUIRED");
    char path[PATH_MAX]; input_path(uid, job_id, path, sizeof(path));
    struct pins pins = {0}; int input = directory_open(path, uid, true, false, &pins);
    int request_fd = openat(input, "request", O_RDONLY|O_NOFOLLOW|O_CLOEXEC); require(request_fd >= 0, "UNAVAILABLE");
    inspect(request_fd, uid, false, false, true); struct request request = request_read(request_fd); close(request_fd);
    require(!strcmp(request.job, job_id) && request.owner.uid == uid, "CONFLICT");
    int job = open_existing_job(&request, &pins); unsigned long long sequence = 0; char phase[32];
    require(receipt_read(job, request.machine ? 0 : uid, !request.machine, job_id, &sequence, phase) &&
        (!strcmp(phase, "SUCCEEDED") || !strcmp(phase, "FAILED") || !strcmp(phase, "CANCELLED")), "OUTCOME_UNKNOWN");
    const char *names[] = {"package.dmg", "commit", "watcher", "request", "vpn-control-install-worker"};
    for (size_t i = 0; i < sizeof(names)/sizeof(names[0]); ++i) {
        int fd = openat(input, names[i], O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
        if (fd < 0 && errno == ENOENT) continue;
        require(fd >= 0, "UNAVAILABLE");
        // The executable is 0700; all other captured records must remain 0600.
        struct stat metadata = inspect(fd, uid, false, false, true);
        require((metadata.st_mode & 0777) == (!strcmp(names[i], "vpn-control-install-worker") ? 0700 : 0600), "INVALID_ARGUMENT");
        require(same_inode(fd, input, names[i]) && unlinkat(input, names[i], 0) == 0, "PERSISTENCE_FAILED"); close(fd);
    }
    char parent_path[PATH_MAX]; text_copy(parent_path, sizeof(parent_path), path); *strrchr(parent_path, '/') = 0;
    int parent = directory_open(parent_path, uid, true, false, &pins);
    // An unexpected extra leaf leaves the directory intact; never recursively erase input.
    require(same_inode(input, parent, job_id), "CONFLICT");
    if (unlinkat(parent, job_id, AT_REMOVEDIR) != 0) require(errno == ENOTEMPTY, "PERSISTENCE_FAILED");
    fsync(parent); release(&pins);
}

int main(int argc, char **argv) {
    require(argc == 4 && (!strcmp(argv[1], "--watch") || !strcmp(argv[1], "--coordinate") || !strcmp(argv[1], "--cleanup")), "INVALID_ARGUMENT");
    job_check(argv[2]); uint64_t requested_pid = number(argv[3], false); require(requested_pid <= INT_MAX, "INVALID_ARGUMENT");
    if (!strcmp(argv[1], "--cleanup")) {
        struct proc_bsdinfo owner; require(generation_snapshot((pid_t)requested_pid, &owner) &&
            owner.pbi_uid == getuid() && owner.pbi_ruid == getuid() && owner.pbi_svuid == getuid(), "CONFLICT");
        cleanup_input(argv[2]); return 0;
    }
    if (!strcmp(argv[1], "--watch")) {
        struct request request = request_read(STDIN_FILENO);
        require(!strcmp(request.job, argv[2]) && request.owner.pid == (pid_t)requested_pid, "CONFLICT");
        watcher(&request); return 0;
    }
    struct proc_bsdinfo owner; require(generation_snapshot((pid_t)requested_pid, &owner), "CONFLICT");
    require(owner.pbi_uid > 0 && owner.pbi_uid == owner.pbi_ruid && owner.pbi_uid == owner.pbi_svuid, "PRIVILEGES_REQUIRED");
    char path[PATH_MAX]; input_path(owner.pbi_uid, argv[2], path, sizeof(path));
    struct pins input_pins = {0}; int input = directory_open(path, owner.pbi_uid, true, false, &input_pins);
    int fd = openat(input, "request", O_RDONLY|O_NOFOLLOW|O_CLOEXEC); require(fd >= 0, "UNAVAILABLE");
    inspect(fd, owner.pbi_uid, false, false, true); struct request request = request_read(fd); close(fd);
    require(!strcmp(request.job, argv[2]) && request.owner.pid == (pid_t)requested_pid && request.owner.uid == owner.pbi_uid &&
        request.owner.seconds == owner.pbi_start_tvsec && request.owner.micros == owner.pbi_start_tvusec, "CONFLICT");
    char expected_package[PATH_MAX]; join(expected_package, sizeof(expected_package), path, "package.dmg");
    require(!strcmp(expected_package, request.package), "CONFLICT");
    coordinator(&request, input); release(&input_pins); return 0;
}
