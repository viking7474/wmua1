#ifndef myjb_hide_h
#define myjb_hide_h

#include "basebin_common.h"

void myjb_hide_start(void);
uint32_t myjb_real_image_count(void);
const char *myjb_real_image_name(uint32_t index);
const struct mach_header *myjb_real_image_header(uint32_t index);

#endif /* myjb_hide_h */
