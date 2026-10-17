#ifndef jbutil_extract_h
#define jbutil_extract_h

#include "common.h"

#define TAR_REGTYPE  '0'
#define TAR_AREGTYPE '\0'
#define TAR_LNKTYPE  '1'
#define TAR_SYMTYPE  '2'
#define TAR_CHRTYPE  '3'
#define TAR_BLKTYPE  '4'
#define TAR_DIRTYPE  '5'
#define TAR_FIFOTYPE '6'

#define TAR_NAME_OFF 0
#define TAR_MODE_OFF 100
#define TAR_UID_OFF 108
#define TAR_GID_OFF 116
#define TAR_TYPEFLAG_OFF 156
#define TAR_LINKNAME_OFF 157
#define TAR_OCTAL_OFF 103
#define TAR_MTIME_OFF 136

#define TAR_UID parse_octal(data + TAR_UID_OFF, 8)
#define TAR_GID parse_octal(data + TAR_GID_OFF, 8)
#define TAR_MODE parse_mode(data + TAR_OCTAL_OFF, &mode)

typedef struct {
    int input_fd;
    uint8_t *input_data;
    uint32_t input_size;
    char *input_path;
    int output_fd;
    uint8_t *output_data;
    uint32_t output_size;
    char *output_path;
    compression_stream stream;
    bool stream_loaded;
    compression_status status;
} lzfse_ctx_t;

int extract_tar(FILE *input, const char *path);
void lzfse_release(lzfse_ctx_t *ctx);
lzfse_ctx_t *lzfse_load(const char *input, const char *output);
int lzfse_decode(lzfse_ctx_t *ctx);
int extract_lzfse_tar(const char *input, const char *output);

#endif /* jbutil_extract_h */
