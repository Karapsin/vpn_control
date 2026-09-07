#include "android_native_string.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define STRING_CHUNK 65536

static void throw_new(JNIEnv *env, const char *type, const char *message) {
    if ((*env)->ExceptionCheck(env)) return;
    jclass exception = (*env)->FindClass(env, type);
    if (exception != NULL) {
        (*env)->ThrowNew(env, exception, message);
        (*env)->DeleteLocalRef(env, exception);
    }
}

jstring vpn_control_construct_string(JNIEnv *env, jobject reader, jint count, jboolean ascii,
                                    void *(*allocate)(size_t), void (*release)(void *)) {
    if (reader == NULL || count < 0 || (ascii != JNI_TRUE && ascii != JNI_FALSE)) {
        throw_new(env, "java/lang/IllegalArgumentException", "Private string input is invalid");
        return NULL;
    }
    if ((uint64_t)count > SIZE_MAX / sizeof(jchar)) {
        throw_new(env, "java/lang/OutOfMemoryError", "Native string input cannot be allocated");
        return NULL;
    }
    if (count == 0) {
        const jchar empty = 0;
        return (*env)->NewString(env, &empty, 0);
    }
    jclass reader_class = (*env)->GetObjectClass(env, reader);
    if (reader_class == NULL) return NULL;
    jmethodID read = (*env)->GetMethodID(env, reader_class, "read", "(JI)[B");
    (*env)->DeleteLocalRef(env, reader_class);
    if (read == NULL) return NULL;

    const size_t allocation_size = (size_t)count * sizeof(jchar);
    jchar *units = allocate(allocation_size);
    if (units == NULL) {
        throw_new(env, "java/lang/OutOfMemoryError", "Native string input cannot be allocated");
        return NULL;
    }
    jstring result = NULL;
    const jlong byte_count = (jlong)count * (ascii ? 1 : 2);
    jlong offset = 0;
    while (offset < byte_count) {
        const size_t remaining = (size_t)(byte_count - offset);
        const size_t length = remaining < STRING_CHUNK ? remaining : STRING_CHUNK;
        jbyteArray chunk = (jbyteArray)(*env)->CallObjectMethod(env, reader, read, offset, (jint)length);
        if ((*env)->ExceptionCheck(env)) goto done;
        if (chunk == NULL || (*env)->GetArrayLength(env, chunk) != (jsize)length) {
            if (chunk != NULL) (*env)->DeleteLocalRef(env, chunk);
            throw_new(env, "java/io/IOException", "Private string input length changed");
            goto done;
        }
        jbyte *bytes = (*env)->GetByteArrayElements(env, chunk, NULL);
        if (bytes == NULL) {
            (*env)->DeleteLocalRef(env, chunk);
            goto done;
        }
        int valid = 1;
        if (ascii) {
            for (size_t index = 0; index < length; index++) {
                const uint8_t unit = (uint8_t)bytes[index];
                if (unit > 127) { valid = 0; break; }
                units[(size_t)offset + (size_t)index] = unit;
            }
        } else {
            for (size_t index = 0; index < length; index += 2) {
                units[(size_t)(offset / 2) + (size_t)(index / 2)] =
                    (jchar)(((uint16_t)(uint8_t)bytes[index] << 8) | (uint8_t)bytes[index + 1]);
            }
        }
        memset(bytes, 0, length);
        (*env)->ReleaseByteArrayElements(env, chunk, bytes, 0);
        (*env)->DeleteLocalRef(env, chunk);
        if ((*env)->ExceptionCheck(env)) goto done;
        if (!valid) {
            throw_new(env, "java/io/IOException", "Private string ASCII input is invalid");
            goto done;
        }
        offset += (jlong)length;
    }
    /* NewString preserves every UTF16 code unit, including NUL and lone surrogates. */
    result = (*env)->NewString(env, units, count);
done:
    /* A callback/JNI exception remains pending and is delivered unchanged. */
    memset(units, 0, allocation_size);
    release(units);
    return result;
}

JNIEXPORT jstring JNICALL
Java_com_kardinal_vpncontrol_data_AndroidNativeString_construct(
    JNIEnv *env, jclass owner, jobject reader, jint count, jboolean ascii) {
    (void)owner;
    return vpn_control_construct_string(env, reader, count, ascii, malloc, free);
}
