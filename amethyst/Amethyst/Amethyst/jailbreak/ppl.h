#ifndef ppl_h
#define ppl_h

#include <stdio.h>

void ppl_write_buf(uint64_t pa, void *data, uint32_t size);
void ppl_write8(uint64_t pa, uint8_t value);
void ppl_write16(uint64_t pa, uint16_t value);
void ppl_write32(uint64_t pa, uint32_t value);
void ppl_write64(uint64_t pa, uint64_t value);
int ppl_init(void);

#endif /* ppl_h */
