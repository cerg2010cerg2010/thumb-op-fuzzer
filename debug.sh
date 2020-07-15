#!/bin/sh
# Connect to remote gdbserver
ROOTDIR=/tmp
GDB=/opt/android-sdk/ndk-bundle/prebuilt/linux-x86_64/bin/gdb

if [ ! -e "$ROOTDIR/system/bin/app_process" ]; then
	mkdir -p $ROOTDIR/system
	mkdir $ROOTDIR/system/bin
	mkdir $ROOTDIR/system/lib
	adb pull /system/bin/app_process $ROOTDIR/system/bin/
	adb pull /system/bin/linker $ROOTDIR/system/bin/
	adb pull /system/lib/libc.so $ROOTDIR/system/lib/
	adb pull /system/lib/libm.so $ROOTDIR/system/lib/
	adb pull /system/lib/libdl.so $ROOTDIR/system/lib/
fi

adb forward tcp:5039 tcp:5039
#adb shell su -c /data/local/tmp/gdbserver :5039 /data/local/tmp/op-fuzzer &
adb shell su -c env LD_PRELOAD= /data/local/tmp/gdbserver :5039 /data/local/tmp/op-fuzzer &
sleep .3

$GDB \
	-ex 'set osabi GNU/Linux' \
	-ex "file obj/local/armeabi-v7a/op-fuzzer" \
	-ex "set solib-search-path $ROOTDIR/system/bin:$ROOTDIR/system/lib:./obj/local/armeabi-v7a" \
	-ex 'set sysroot target:' \
	-ex 'set follow-fork-mode child' \
	-ex 'set detach-on-fork off' \
	-ex 'target remote :5039'

