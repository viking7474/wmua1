CC = $(shell xcrun --sdk iphoneos --find clang)
STRIP = $(shell xcrun --sdk iphoneos --find strip)
SDK = $(shell xcrun --sdk iphoneos --show-sdk-path)
LDID = $(shell which ldid)

CFLAGS := -I./include -I../common/include -isysroot $(SDK) -mios-version-min=12.0 -arch arm64e -arch arm64 \
	-Werror -Wall -Wno-unused-variable -Wno-unused-function -fvisibility=hidden -fvisibility-inlines-hidden
LDFLAGS := -L$(SDK)/usr/lib -lc -lSystem -dynamiclib

SRC = $(wildcard src/*.c) $(wildcard ../common/src/*.c) $(wildcard ../common/src/*.s)

all: $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o base_hook.dylib $^
	$(STRIP) -x base_hook.dylib
	$(LDID) -S base_hook.dylib

clean:
	@rm -rf base_hook.dylib
	@rm -rf base_hook.dylib.dSYM
	@rm -rf *.o
