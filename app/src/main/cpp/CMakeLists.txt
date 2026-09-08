cmake_minimum_required(VERSION 3.22.1)
project(vpn_control_strings LANGUAGES C)

add_library(vpn_control_strings SHARED android_native_string.c android_native_publication.c)
target_compile_features(vpn_control_strings PRIVATE c_std_11)
set_target_properties(vpn_control_strings PROPERTIES C_VISIBILITY_PRESET hidden)

if(NOT ANDROID)
    if(NOT VPN_CONTROL_JNI_INCLUDE_DIR OR NOT VPN_CONTROL_JNI_PLATFORM_DIR)
        message(FATAL_ERROR "Host string tests require explicit Gradle JDK JNI include directories")
    endif()
    target_include_directories(vpn_control_strings PRIVATE
        "${VPN_CONTROL_JNI_INCLUDE_DIR}" "${VPN_CONTROL_JNI_PLATFORM_DIR}")
    option(VPN_CONTROL_HOST_TESTS "Build host-only native allocator regression hooks" OFF)
    if(VPN_CONTROL_HOST_TESTS)
        target_sources(vpn_control_strings PRIVATE ../../test/cpp/android_native_string_test.c)
    endif()
endif()

if(MSVC)
    target_compile_options(vpn_control_strings PRIVATE /W4 /WX)
else()
    target_compile_options(vpn_control_strings PRIVATE -Wall -Wextra -Werror)
endif()
