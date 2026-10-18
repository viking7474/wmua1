CC = $(shell xcrun --sdk iphoneos --find clang)
STRIP = $(shell xcrun --sdk iphoneos --find strip)
SDK = $(shell xcrun --sdk iphoneos --show-sdk-path)
LDID = $(shell which ldid)

CFLAGS := -I./include -I./vendor -I../common/include -isysroot $(SDK) -mios-version-min=12.0 -arch arm64e -arch arm64 \
	-Werror -Wall -Wno-unused-variable -Wno-unused-function -fvisibility=hidden -fvisibility-inlines-hidden -fblocks
LDFLAGS := -L$(SDK)/usr/lib -lc -lSystem -dynamiclib

SRC = $(wildcard src/*.c) $(wildcard vendor/*.c)
COMMON_SRC = $(wildcard ../common/src/*.c) $(wildcard ../common/src/*.s)

all: $(SRC) $(COMMON_SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o myjb_loader.dylib $(SRC) $(COMMON_SRC)
	$(STRIP) -x myjb_loader.dylib
	$(LDID) -S myjb_loader.dylib

clean:
	@rm -rf myjb_loader.dylib
	@rm -rf myjb_loader.dylib.dSYM
	@rm -rf *.o
