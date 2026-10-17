# myJB checkm8 tool (fork of openra1n, Apache-2.0)
#
# Windows (cross, MinGW via CI):
#   make LIBUSB=1 WINDOWS_CROSS=1 LIBUSB_MINGW=/path/to/libusb-1.0.27
# Linux:
#   make LIBUSB=1
# macOS (IOKit backend; payload upload requires libusb build):
#   make

CFLAGS = -I./include -Wall -Wno-pointer-sign
CFLAGS += -Os
BIN = myjb_ktool$(EXE)
SOURCE = openra1n.c lz4/lz4.c lz4/lz4hc.c

ifdef WINDOWS_CROSS
	EXE = .exe
	CC = x86_64-w64-mingw32-gcc
	STRIP = x86_64-w64-mingw32-strip
	CFLAGS += -DHAVE_LIBUSB -D_WIN32_WINNT=0x0601 -I$(LIBUSB_MINGW)/include
	LDFLAGS += -L$(LIBUSB_MINGW)/MinGW64/static -lusb-1.0 -lsetupapi -lole32 -static -static-libgcc
else ifeq ($(LIBUSB),1)
	CC = gcc
	CFLAGS += -DHAVE_LIBUSB
	LDFLAGS += -lusb-1.0
else
	CC = xcrun -sdk macosx gcc
	CFLAGS += -arch x86_64 -arch arm64
	LDFLAGS += -framework IOKit -framework CoreFoundation
endif

STRIP ?= strip

.PHONY: all clean payloads

all: payloads $(BIN)

payloads:
	@mkdir -p include/payloads
	@for file in payloads/*; do \
		echo " XXD    $$file"; \
		xxd -i $$file > include/$$file.h; \
	done

$(BIN): payloads
	@echo " CC     $(BIN)"
	@$(CC) $(CFLAGS) $(SOURCE) $(LDFLAGS) -o $(BIN)
	-@$(STRIP) $(BIN) 2>/dev/null || true

clean:
	@echo " CLEAN  $(BIN)"
	@rm -f myjb_ktool myjb_ktool.exe
	@echo " CLEAN  include/payloads"
	@rm -rf include/payloads
