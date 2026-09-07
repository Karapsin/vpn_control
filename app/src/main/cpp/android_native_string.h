#ifndef VPN_CONTROL_ANDROID_NATIVE_STRING_H
#define VPN_CONTROL_ANDROID_NATIVE_STRING_H

#include <jni.h>
#include <stddef.h>

/* Allocator arguments permit deterministic host tests, never a Java runtime option. */
jstring vpn_control_construct_string(JNIEnv *env, jobject reader, jint count, jboolean ascii,
                                    void *(*allocate)(size_t), void (*release)(void *));

#endif
