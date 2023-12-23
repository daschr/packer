#include "utils.h"
#include "winnt.h"

#include <stdint.h>
#include <string.h>
#include <windows.h>
#include <stdio.h>

uint8_t cmp_bytes(const uint8_t *a, const uint8_t *b, size_t len) {
    for(size_t i=0; i<len; ++i) {
        if(a[i]!=b[i])
            return 0;
    }
    return 1;
}

uint64_t round_up(uint64_t i, uint64_t step) {
    uint64_t r = i%step;
    if(r==0) {
        return i;
    }

    return i+step-r;
}

void pe_free(pe_t *self) {
    free(self->info.section_table);
    free(self);
}

size_t pe_get_len(const pe_t *self) {
    size_t len = self->info.end_of_header;
    for(size_t s=0; s<self->info.file_header.NumberOfSections; ++s) {
        len+=round_up(self->info.section_table[s].Misc.VirtualSize, self->info.optional_header.opt_header64.SectionAlignment);
    }

    return round_up(len, self->info.optional_header.opt_header64.SectionAlignment);
}

uint8_t pe_load_aligned_into_memory(const pe_t *self, uint8_t *mem, size_t mem_size) {
    memcpy(mem, self->data, self->info.end_of_header);

    const size_t alignment = self->info.optional_header.opt_header64.SectionAlignment;

    size_t aligned_mem_pos = round_up(self->info.end_of_header, alignment);

    IMAGE_SECTION_HEADER *section_table=self->info.section_table;
    for(size_t i=0; i<self->info.file_header.NumberOfSections; ++i) {
        if(aligned_mem_pos + section_table[i].SizeOfRawData > mem_size) {
            fprintf(stderr, "Failed to load section %llu into memory: %llu > %llu\n", i,
                    aligned_mem_pos + section_table[i].SizeOfRawData, mem_size);
            return 0;
        }

        memcpy(mem + section_table[i].VirtualAddress, self->data+section_table[i].PointerToRawData, section_table[i].SizeOfRawData);
        aligned_mem_pos+=round_up(section_table[i].Misc.VirtualSize, alignment);
    }

    return 1;
}

uint8_t pe_load_imports(const pe_t *self, uint8_t *mem, size_t mem_size) {
    const IMAGE_DATA_DIRECTORY *data_dir = self->info.is_64bit?
                                           self->info.optional_header.opt_header64.DataDirectory
                                           :self->info.optional_header.opt_header32.DataDirectory;

    if(data_dir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress==0) {
        fprintf(stderr, "[pe_load_imports] got no imports\n");
        return 1;
    }

    const uint64_t address_mask = self->info.is_64bit?UINT64_MAX>>1:UINT32_MAX>>1;
    IMAGE_IMPORT_DESCRIPTOR *import_table = (IMAGE_IMPORT_DESCRIPTOR *) (mem + data_dir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    while(import_table->OriginalFirstThunk != 0) {
        char *dll_name =(char *) (mem + import_table->Name);
        HMODULE lib = LoadLibraryA(dll_name);
        if(lib==NULL) {
            fprintf(stderr, "Could not load library \"%s\"\n", dll_name);
            return 0;
        }

        IMAGE_THUNK_DATA64 *lookup_table=(IMAGE_THUNK_DATA64 *)(mem+import_table->OriginalFirstThunk);
        IMAGE_THUNK_DATA64 *address_table=(IMAGE_THUNK_DATA64 *)(mem+import_table->FirstThunk);

        while(lookup_table->u1.AddressOfData != 0) {
            FARPROC fn = NULL;
            uint64_t lookup_address = lookup_table->u1.AddressOfData;


            if((lookup_address & IMAGE_ORDINAL_FLAG64) != 0) {
                char *fn_ordinal = (char *) (lookup_address & address_mask);
                fn = GetProcAddress(lib, fn_ordinal);
                if(fn == NULL) {
                    fprintf(stderr, "Failed to find %llx (ordinal) in \"%s\"\n", (uint64_t) fn_ordinal, dll_name);
                    return 0;
                }
            } else {
                IMAGE_IMPORT_BY_NAME *import = (IMAGE_IMPORT_BY_NAME *) (mem + lookup_address);
                fn = GetProcAddress(lib, import->Name);
                if(fn == NULL) {
                    fprintf(stderr, "Failed to find \"%s\" (non-ordinal) in \"%s\"\n", import->Name, dll_name);
                    return 0;
                }
            }

            address_table->u1.Function=(uint64_t) fn;


            ++lookup_table;
            ++address_table;
        }

        ++import_table;
    }

    return 1;
}

uint8_t pe_relocate_in_mem(const pe_t *self, uint8_t *mem, size_t mem_size) {
    if((self->info.optional_header.opt_header64.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) == 0) {
        fprintf(stderr, "Cannot relocate pe, missing characteristic\n");
        return 0;
    }

    const IMAGE_DATA_DIRECTORY *basereloc = (self->info.is_64bit?
                                            self->info.optional_header.opt_header64.DataDirectory
                                            :self->info.optional_header.opt_header32.DataDirectory) + IMAGE_DIRECTORY_ENTRY_BASERELOC;

    if(basereloc->VirtualAddress == 0) {
        fprintf(stderr, "[pe_relocate_in_mem] Relocation table is empty\n");
        return 1;
    }

    int64_t delta = (int64_t) mem - self->info.optional_header.opt_header64.ImageBase;

    IMAGE_BASE_RELOCATION *relocation_table = (IMAGE_BASE_RELOCATION *) (mem + basereloc->VirtualAddress);

    while(relocation_table->VirtualAddress) {
        size_t num_relocations = (relocation_table->SizeOfBlock-sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);
        uint16_t *relocation_data=(uint16_t *) &relocation_table[1];

        for(size_t i=0; i<num_relocations; ++i) {
            uint16_t type = relocation_data[i]>>12;
            uint16_t offset = relocation_data[i]&0xfff;

            uint8_t **ptr = (uint8_t **) (mem + relocation_table->VirtualAddress + offset);

            if(type == IMAGE_REL_BASED_DIR64) {
                if((uint64_t) ptr> (uint64_t) mem+mem_size) {
                    fprintf(stderr, "ptr: %p is bigger than mem + memsize: %p\n", (void *) ptr, (void *) (mem + mem_size));
                    return 0;
                } else {
                    *ptr+=delta;
                }
            }
        }


        relocation_table = (IMAGE_BASE_RELOCATION *)(((uint8_t *) relocation_table) + relocation_table->SizeOfBlock);
    }

    return 1;
}

uint8_t pe_load_into_memory(const pe_t *self, uint8_t *mem, size_t mem_size) {
    if(!pe_load_aligned_into_memory(self, mem, mem_size)) {
        return 0;
    }

    if(!pe_load_imports(self, mem, mem_size)) {
        return 0;
    }

    if(!pe_relocate_in_mem(self, mem, mem_size)) {
        return 0;
    }

    return 1;
}

pe_t *pe_new(const uint8_t *data, size_t data_len) {
    if(data_len < 4)
        return 0;

    pe_t *self=malloc(sizeof(pe_t));
    memset(self, 0, sizeof(pe_t));
    self->data=data;
    self->data_len=data_len;

    size_t pos=0;

    memcpy(&self->info.mz_header, data+pos, sizeof(mz_header_t));
    pos+=sizeof(mz_header_t);

    pos=self->info.mz_header.offsetToPE;
    pos+=4;


    memcpy(&self->info.file_header, data+pos, sizeof(IMAGE_FILE_HEADER));
    pos+=sizeof(IMAGE_FILE_HEADER);

    if((data[pos+1] == 0x01 || data[pos+1] == 0x02) && data[pos] == 0x0b) {
        self->info.is_64bit=data[pos+1] == 0x02;
    } else {
        fprintf(stderr, "Opt header magic not found: %02x %02x\n", data[pos], data[pos+1]);
        goto error;
    }

    const size_t opt_header_size = self->info.is_64bit?sizeof(IMAGE_OPTIONAL_HEADER64):sizeof(IMAGE_OPTIONAL_HEADER32);

    memcpy(&(self->info.optional_header), data+pos, opt_header_size);

    pos+=opt_header_size;

    self->info.section_table = malloc(sizeof(IMAGE_SECTION_HEADER)*self->info.file_header.NumberOfSections);

    if(self->info.section_table==NULL) {
        goto error;
    }

    if(data_len  < pos+sizeof(IMAGE_SECTION_HEADER)*self->info.file_header.NumberOfSections) {
        goto error;
    }

    for(size_t i=0; i<self->info.file_header.NumberOfSections; ++i) {
        memcpy( &(self->info.section_table[i]),
                data+pos+sizeof(IMAGE_SECTION_HEADER)*i,
                sizeof(IMAGE_SECTION_HEADER));
    }

    self->info.end_of_header = pos+sizeof(IMAGE_SECTION_HEADER)*self->info.file_header.NumberOfSections;

    return self;

error:
    pe_free(self);
    return NULL;
}
