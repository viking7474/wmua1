#include "jailbreak.h"
#include "utils.h"
#include "nvram.h"

void nvram_close(nvram_handle_t *handle) {
    if (handle == NULL) return;
    if (MACH_PORT_VALID(handle->ap_client)) {
        mach_port_deallocate(mach_task_self(), handle->ap_client);
    }
    
    if (MACH_PORT_VALID(handle->ap_service)) {
        mach_port_deallocate(mach_task_self(), handle->ap_service);
    }
    
    if (MACH_PORT_VALID(handle->dt_service)) {
        mach_port_deallocate(mach_task_self(), handle->dt_service);
    }
    
    remove_cs_flag(getpid(), CS_NVRAM_UNRESTRICTED);
    free(handle);
}

nvram_handle_t *nvram_open(void) {
    nvram_handle_t *handle = calloc(1, sizeof(nvram_handle_t));
    if (handle == NULL) return NULL;
    
    add_cs_flag(getpid(), CS_NVRAM_UNRESTRICTED);
    handle->dt_service = IOServiceGetMatchingService(0, IOServiceMatching("IODTNVRAM"));
    if (!MACH_PORT_VALID(handle->dt_service)) {
        nvram_close(handle);
        return NULL;
    }
    
    handle->ap_service = IOServiceGetMatchingService(0, IOServiceMatching("AppleMobileApNonce"));
    if (!MACH_PORT_VALID(handle->ap_service)) {
        nvram_close(handle);
        return NULL;
    }
    
    IOServiceOpen(handle->ap_service, mach_task_self(), 0, &handle->ap_client);
    if (!MACH_PORT_VALID(handle->ap_client)) {
        nvram_close(handle);
        return NULL;
    }
    
    uint64_t dt_port_addr = find_ipc_port(handle->dt_service);
    if (dt_port_addr != 0) {
        handle->dt_object_addr = kread64(dt_port_addr + koffsetof(ipc_port, ip_kobject));
    }
    
    uint64_t ap_port_addr = find_ipc_port(handle->ap_service);
    if (ap_port_addr != 0) {
        handle->ap_object_addr = kread64(ap_port_addr + koffsetof(ipc_port, ip_kobject));
    }
    
    if (handle->dt_object_addr == 0 || handle->ap_object_addr == 0) {
        nvram_close(handle);
        return NULL;
    }
    return handle;
}

int nvram_normalize_generator(char *generator, char *output) {
    if (generator == NULL || output == NULL || strnlen(generator, 18) != 18) return -1;
    if (generator[0] != '0' || generator[1] != 'x') return -1;
    for (int i = 2; i < 18; i++) {
        if (!isxdigit(generator[i])) return -1;
    }
    
    CFStringRef str = CFStringCreateWithCString(NULL, generator, kCFStringEncodingUTF8);
    if (str == NULL) return -1;
    
    CFMutableStringRef output_str = CFStringCreateMutableCopy(NULL, CFStringGetLength(str), str);
    CFStringLowercase(output_str, CFLocaleCopyCurrent());
    CFRelease(str);
    
    int status = CFStringGetCString(output_str, output, 20-1, kCFStringEncodingUTF8) ? 0 : -1;
    CFRelease(output_str);
    return status;
}

int nvram_create_generator(nvram_handle_t *handle) {
    if (handle == NULL) return -1;
    uint8_t value[48] = {0};
    size_t size = sizeof(value);
    return IOConnectCallStructMethod(handle->ap_client, 200, NULL, 0, value, &size);
}

int nvram_sync(nvram_handle_t *handle) {
    if (handle == NULL) return -1;
    usleep(100000);

    CFMutableDictionaryRef dict = CFDictionaryCreateMutable(NULL, 0, NULL, NULL);
    CFDictionarySetValue(dict, CFSTR("temp_amethyst"), CFSTR("0x1337"));
    CFDictionarySetValue(dict, CFSTR("IONVRAM-DELETE-PROPERTY"), CFSTR("temp_amethyst"));
    CFDictionarySetValue(dict, CFSTR("IONVRAM-FORCESYNCNOW-PROPERTY"), CFSTR("com.apple.System.boot-nonce"));
    
    int status = IORegistryEntrySetCFProperties(handle->dt_service, dict);
    CFRelease(dict);
    return status;
}

uint64_t nvram_find_key(nvram_handle_t *handle, uint64_t key) {
    if (handle == NULL || key == 0) return 0;
    uint64_t nvram_dict = kread64(handle->dt_object_addr + 0xc0);
    if (nvram_dict == 0) return 0;

    uint32_t dict_count = kread32(nvram_dict + 0x14);
    if (dict_count == 0) return 0;
    
    uint64_t dict_entry = kread64(nvram_dict + 0x20);
    if (dict_entry == 0) return 0;

    nvram_entry_t *entry_list = calloc(1, sizeof(nvram_entry_t) * (dict_count + 1));
    if (entry_list == NULL) return 0;
    
    kread_buf(dict_entry, entry_list, sizeof(nvram_entry_t) * dict_count);
    uint64_t value = 0;
    
    for (uint32_t i = 0; i < dict_count; i++) {
        if (entry_list[i].key == key) {
            value = entry_list[i].value;
            if (value != 0) break;
        }
    }
    
    free(entry_list);
    return value;
}

int nvram_set_generator(char *generator) {
    char new_generator[20] = {0};
    if (nvram_normalize_generator(generator, &new_generator[0]) != 0) return -1;
    int status = -1;

    nvram_handle_t *handle = nvram_open();
    if (handle == NULL) goto done;
    
    uint64_t target_key = kread64(handle->ap_object_addr + 0xc0);
    if (target_key == 0) goto done;

    uint64_t generator_entry = nvram_find_key(handle, target_key);
    if (generator_entry == 0) {
        if (nvram_create_generator(handle) == 0) {
            usleep(10000);
            generator_entry = nvram_find_key(handle, target_key);
        }
        if (generator_entry == 0) goto done;
    }
    
    uint64_t generator_addr = kread64(generator_entry + 0x10);
    if (generator_addr == 0) goto done;
    
    char current_generator[20] = {0};
    kread_buf(generator_addr, current_generator, 18);
    
    if (strcasecmp(current_generator, new_generator) != 0) {
        kwrite_buf(generator_addr, new_generator, 18);
        nvram_sync(handle);
    }
    status = 0;

done:
    nvram_close(handle);
    return status;
}
