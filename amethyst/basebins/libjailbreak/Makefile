CC = $(shell xcrun --sdk iphoneos --find clang)
STRIP = $(shell xcrun --sdk iphoneos --find strip)
SDK = $(shell xcrun --sdk iphoneos --show-sdk-path)
LDID = $(shell which ldid)

CFLAGS := -I./include -isysroot $(SDK) -mios-version-min=12.0 -arch arm64e -arch arm64 \
	-Werror -Wall -Wno-unused-variable -Wno-unused-function -fvisibility=hidden -fvisibility-inlines-hidden \
	-DBASEBIN_EXPORT='__attribute__((__visibility__("default")))'
LDFLAGS := -L$(SDK)/usr/lib -lc -lSystem -dynamiclib -Wl,-exported_symbols_list,../resources/exports/libjailbreak.txt


SRC = $(wildcard src/*.c)

all: $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o libjailbreak.dylib $^
	$(STRIP) -x libjailbreak.dylib
	$(LDID) -S libjailbreak.dylib

clean:
	@rm -rf libjailbreak.dylib
	@rm -rf libjailbreak.dylib.dSYM
	@rm -rf *.o
