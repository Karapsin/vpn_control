#define _GNU_SOURCE

#include <jni.h>

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>

#if defined(_WIN32)
#include <windows.h>
#elif defined(__APPLE__)
#include <sys/stat.h>
#include <sys/stdio.h>
#else
#include <fcntl.h>
#include <linux/fs.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif

static void throw_exception(JNIEnv *env, const char *type, const char *message) {
    if ((*env)->ExceptionCheck(env)) return;
    jclass exception = (*env)->FindClass(env, type);
    if (exception != NULL) {
        (*env)->ThrowNew(env, exception, message);
        (*env)->DeleteLocalRef(env, exception);
    }
}

static int valid_utf16(const jchar *units, jsize length) {
    if (length <= 0) return 0;
    for (jsize index = 0; index < length; index++) {
        const jchar unit = units[index];
        if (unit == 0) return 0;
        if (unit >= 0xd800 && unit <= 0xdbff) {
            if (++index >= length || units[index] < 0xdc00 || units[index] > 0xdfff) return 0;
        } else if (unit >= 0xdc00 && unit <= 0xdfff) {
            return 0;
        }
    }
    return 1;
}

#if defined(_WIN32)
static int same_file(const wchar_t *source, const wchar_t *target) {
    HANDLE source_handle = CreateFileW(source, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (source_handle == INVALID_HANDLE_VALUE) return 0;
    HANDLE target_handle = CreateFileW(target, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (target_handle == INVALID_HANDLE_VALUE) { CloseHandle(source_handle); return 0; }
    BY_HANDLE_FILE_INFORMATION source_info;
    BY_HANDLE_FILE_INFORMATION target_info;
    const int same = GetFileInformationByHandle(source_handle, &source_info) &&
        GetFileInformationByHandle(target_handle, &target_info) &&
        source_info.dwVolumeSerialNumber == target_info.dwVolumeSerialNumber &&
        source_info.nFileIndexHigh == target_info.nFileIndexHigh &&
        source_info.nFileIndexLow == target_info.nFileIndexLow;
    CloseHandle(target_handle);
    CloseHandle(source_handle);
    return same;
}

static wchar_t *native_path(JNIEnv *env, jstring value) {
    if (value == NULL) {
        throw_exception(env, "java/io/IOException", "Native publication path is invalid");
        return NULL;
    }
    const jsize length = (*env)->GetStringLength(env, value);
    const jchar *units = (*env)->GetStringChars(env, value, NULL);
    if (units == NULL) return NULL;
    if (!valid_utf16(units, length)) {
        (*env)->ReleaseStringChars(env, value, units);
        throw_exception(env, "java/io/IOException", "Native publication path is invalid");
        return NULL;
    }
    if ((size_t)length > (SIZE_MAX / sizeof(wchar_t)) - 1) {
        (*env)->ReleaseStringChars(env, value, units);
        throw_exception(env, "java/lang/OutOfMemoryError", "Native publication path cannot be allocated");
        return NULL;
    }
    wchar_t *path = malloc(((size_t)length + 1) * sizeof(wchar_t));
    if (path == NULL) {
        (*env)->ReleaseStringChars(env, value, units);
        throw_exception(env, "java/lang/OutOfMemoryError", "Native publication path cannot be allocated");
        return NULL;
    }
    for (jsize index = 0; index < length; index++) path[index] = (wchar_t)units[index];
    path[length] = L'\0';
    (*env)->ReleaseStringChars(env, value, units);
    return path;
}
#else
static int same_file(const char *source, const char *target) {
    struct stat source_info;
    struct stat target_info;
    return stat(source, &source_info) == 0 && stat(target, &target_info) == 0 &&
        source_info.st_dev == target_info.st_dev && source_info.st_ino == target_info.st_ino;
}

static char *native_path(JNIEnv *env, jstring value) {
    if (value == NULL) {
        throw_exception(env, "java/io/IOException", "Native publication path is invalid");
        return NULL;
    }
    const jsize length = (*env)->GetStringLength(env, value);
    const jchar *units = (*env)->GetStringChars(env, value, NULL);
    if (units == NULL) return NULL;
    if (!valid_utf16(units, length) || (size_t)length > (SIZE_MAX - 1) / 3) {
        (*env)->ReleaseStringChars(env, value, units);
        throw_exception(env, "java/io/IOException", "Native publication path is invalid");
        return NULL;
    }
    char *path = malloc((size_t)length * 3 + 1);
    if (path == NULL) {
        (*env)->ReleaseStringChars(env, value, units);
        throw_exception(env, "java/lang/OutOfMemoryError", "Native publication path cannot be allocated");
        return NULL;
    }
    size_t output = 0;
    for (jsize index = 0; index < length; index++) {
        uint32_t code_point = units[index];
        if (code_point >= 0xd800 && code_point <= 0xdbff) {
            code_point = 0x10000 + ((code_point - 0xd800) << 10) + (units[++index] - 0xdc00);
        }
        if (code_point <= 0x7f) {
            path[output++] = (char)code_point;
        } else if (code_point <= 0x7ff) {
            path[output++] = (char)(0xc0 | (code_point >> 6));
            path[output++] = (char)(0x80 | (code_point & 0x3f));
        } else if (code_point <= 0xffff) {
            path[output++] = (char)(0xe0 | (code_point >> 12));
            path[output++] = (char)(0x80 | ((code_point >> 6) & 0x3f));
            path[output++] = (char)(0x80 | (code_point & 0x3f));
        } else {
            path[output++] = (char)(0xf0 | (code_point >> 18));
            path[output++] = (char)(0x80 | ((code_point >> 12) & 0x3f));
            path[output++] = (char)(0x80 | ((code_point >> 6) & 0x3f));
            path[output++] = (char)(0x80 | (code_point & 0x3f));
        }
    }
    path[output] = '\0';
    (*env)->ReleaseStringChars(env, value, units);
    return path;
}
#endif

JNIEXPORT jboolean JNICALL
Java_com_kardinal_vpncontrol_data_AndroidNativePublication_publishNoReplace(
    JNIEnv *env, jclass owner, jstring source_value, jstring target_value) {
    (void)owner;
    jboolean result = JNI_FALSE;
#if defined(_WIN32)
    wchar_t *source = native_path(env, source_value);
    if (source == NULL) return JNI_FALSE;
    wchar_t *target = native_path(env, target_value);
    if (target == NULL) { free(source); return JNI_FALSE; }
    // This only rejects aliases of the same existing file. The native exclusive
    // move remains the authority for every distinct source/target pair.
    if (same_file(source, target)) {
        result = JNI_FALSE;
    } else if (MoveFileExW(source, target, MOVEFILE_WRITE_THROUGH)) {
        result = JNI_TRUE;
    } else {
        const DWORD error = GetLastError();
        if (error != ERROR_FILE_EXISTS && error != ERROR_ALREADY_EXISTS) {
            throw_exception(env, "java/io/IOException", "Native publication failed");
        }
    }
    free(target);
    free(source);
#elif defined(__APPLE__)
    char *source = native_path(env, source_value);
    if (source == NULL) return JNI_FALSE;
    char *target = native_path(env, target_value);
    if (target == NULL) { free(source); return JNI_FALSE; }
    if (same_file(source, target)) {
        result = JNI_FALSE;
    } else if (renamex_np(source, target, RENAME_EXCL) == 0) {
        result = JNI_TRUE;
    } else if (errno != EEXIST) {
        throw_exception(env, "java/io/IOException", "Native publication failed");
    }
    free(target);
    free(source);
#else
    char *source = native_path(env, source_value);
    if (source == NULL) return JNI_FALSE;
    char *target = native_path(env, target_value);
    if (target == NULL) { free(source); return JNI_FALSE; }
    if (same_file(source, target)) {
        result = JNI_FALSE;
    } else if (syscall(SYS_renameat2, AT_FDCWD, source, AT_FDCWD, target, RENAME_NOREPLACE) == 0) {
        result = JNI_TRUE;
    } else if (errno != EEXIST) {
        throw_exception(env, "java/io/IOException", "Native publication failed");
    }
    free(target);
    free(source);
#endif
    return result;
}
