#ifndef nvram_h
#define nvram_h

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <mach/mach.h>
#include <CoreFoundation/CoreFoundation.h>
#include <dlfcn.h>

typedef struct {
    mach_port_t dt_service;
    mach_port_t ap_service;
    mach_port_t ap_client;
    uint64_t dt_object_addr;
    uint64_t ap_object_addr;
} nvram_handle_t;

typedef struct {
    uint64_t key;
    uint64_t value;
} nvram_entry_t;

void nvram_close(nvram_handle_t *handle);
nvram_handle_t *nvram_open(void);
int nvram_normalize_generator(char *generator, char *output);
int nvram_create_generator(nvram_handle_t *handle);
int nvram_sync(nvram_handle_t *handle);
uint64_t nvram_find_key(nvram_handle_t *handle, uint64_t key);
int nvram_set_generator(char *generator);

#endif /* nvram_h */
