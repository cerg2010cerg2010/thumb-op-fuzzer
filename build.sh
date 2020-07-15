#!/bin/sh
ndk-build \
	NDK_PROJECT_PATH=. \
       	APP_BUILD_SCRIPT=./Android.mk \
	APP_ABI=armeabi-v7a \
	TARGET_CFLAGS="-Wno-error=format-security -mfpu=vfpv3-d16" \
	LOCAL_ARM_NEON=false \
	$@
