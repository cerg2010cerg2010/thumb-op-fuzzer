LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
	main.c

LOCAL_CFLAGS += -Werror -mcpu=cortex-a9 -mfloat-abi=softfp -mfpu=vfpv3-d16
LOCAL_CFLAGS += -fvisibility=hidden
LOCAL_MODULE := op-fuzzer
LOCAL_MODULE_TAGS := optional

include $(BUILD_EXECUTABLE)
