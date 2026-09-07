#include "../../main/cpp/android_native_string.h"
#include <stdlib.h>
#include <stdatomic.h>

static atomic_int live_allocations = 0;
static void *counted_allocate(size_t size) {
    void *value = malloc(size);
    if (value != NULL) atomic_fetch_add(&live_allocations, 1);
    return value;
}
static void counted_release(void *value) {
    if (value != NULL) atomic_fetch_sub(&live_allocations, 1);
    free(value);
}
static void *failed_allocate(size_t size) { (void)size; return NULL; }

JNIEXPORT jstring JNICALL
Java_com_kardinal_vpncontrol_data_AndroidNativeStringTestHooks_construct(
    JNIEnv *env, jclass owner, jobject reader, jint count, jboolean ascii, jboolean fail_allocation) {
    (void)owner;
    return vpn_control_construct_string(env, reader, count, ascii,
                                       fail_allocation ? failed_allocate : counted_allocate, counted_release);
}

JNIEXPORT jint JNICALL
Java_com_kardinal_vpncontrol_data_AndroidNativeStringTestHooks_liveAllocations(JNIEnv *env, jclass owner) {
    (void)env; (void)owner;
    return atomic_load(&live_allocations);
}
