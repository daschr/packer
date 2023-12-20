#include "utils.h"
#include "winnt.h"

#include <stdint.h>
#include <string.h>
#include <windows.h>
#include <stdio.h>

uint8_t cmp_bytes(const uint8_t *a, const uint8_t *b, size_t len) {
  for(size_t i=0;i<len;++i){
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

void pe_free(pe_t *self){
  free(self->info.section_table);
  free(self);
}

size_t pe_get_len(const pe_t *self) {
  size_t len = self->info.end_of_header;
  for(size_t s=0;s<self->info.file_header.NumberOfSections;++s){
    len+=self->info.section_table[s].Misc.VirtualSize; 
  }

  return round_up(len, self->info.optional_header.opt_header64.SectionAlignment);
}

uint8_t pe_load_aligned_into_memory(const pe_t *self, uint8_t *mem, size_t mem_size) {
  memcpy(mem, self->data, self->info.end_of_header);
  
  const size_t alignment = self->info.optional_header.opt_header64.SectionAlignment;
  
  size_t aligned_mem_pos = round_up(self->info.end_of_header, alignment); 

  IMAGE_SECTION_HEADER *section_table=self->info.section_table;
  for(size_t i=0;i<self->info.file_header.NumberOfSections;++i){
    if(aligned_mem_pos + section_table[i].SizeOfRawData > mem_size){
      fprintf(stderr, "Failed to load section %llu into memory: %llu > %llu\n", i, 
        aligned_mem_pos + section_table[i].SizeOfRawData, mem_size      );
      return 0;
    }
    printf("[pe_load_aligned_into_memory] storing section \"%s\"\n\
    PointerToRawData: %lx\n\
    SizeOfRawData: %lx\n\
    VirtualAddress: %lx\n\
    into %p\n\n",  
      section_table[i].Name, 
      section_table[i].PointerToRawData,
      section_table[i].SizeOfRawData,
      section_table[i].VirtualAddress,
      mem+section_table[i].VirtualAddress);

    memcpy(mem + section_table[i].VirtualAddress, self->data+section_table[i].PointerToRawData, section_table[i].SizeOfRawData);
    aligned_mem_pos+=round_up(section_table[i].Misc.VirtualSize, alignment);  
  }

  printf("[pe_load_aligned_into_memory] aligned_mem_pos: %p\n", mem+aligned_mem_pos);

  return 1; 
}

uint8_t pe_load_imports(const pe_t *self, uint8_t *mem, size_t mem_size){
  const IMAGE_DATA_DIRECTORY *data_dir = self->info.is_64bit?
    self->info.optional_header.opt_header64.DataDirectory
    :self->info.optional_header.opt_header32.DataDirectory;

  if(data_dir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress==0){
    printf("[pe_load_imports] got no imports\n");
    return 1;
  }
  
  IMAGE_IMPORT_DESCRIPTOR *import_table = (IMAGE_IMPORT_DESCRIPTOR *) (mem + data_dir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

  while(import_table->OriginalFirstThunk != 0){
    char *dll_name =(char *) (mem + import_table->Name);
    HMODULE lib = LoadLibraryA(dll_name);
    if(lib==NULL){
      fprintf(stderr, "Could not load library \"%s\"\n", dll_name);
      return 0;
    }

    IMAGE_THUNK_DATA64 *lookup_table=(IMAGE_THUNK_DATA64 *)(mem+import_table->OriginalFirstThunk);
    IMAGE_THUNK_DATA64 *address_table=(IMAGE_THUNK_DATA64 *)(mem+import_table->FirstThunk);

    while(lookup_table->u1.AddressOfData != 0){
      FARPROC fn = NULL;
      uint64_t lookup_address = lookup_table->u1.AddressOfData;

      if((lookup_address & IMAGE_ORDINAL_FLAG64) != 0) {
        char *fn_name = (char *) (lookup_address & 0xffffffff);
        fn = GetProcAddress(lib, fn_name);
        if(fn == NULL){
          fprintf(stderr, "Failed to find \"%s\" in \"%s\"", fn_name, dll_name);
          return 0;
        }
        printf("Loading \"%s\" from \"%s\"\n", fn_name, dll_name);
      }else{
        IMAGE_IMPORT_BY_NAME *import = (IMAGE_IMPORT_BY_NAME *) (mem + lookup_address);
        fn = GetProcAddress(lib, import->Name);
        if(fn == NULL){
          fprintf(stderr, "Failed to find \"%s\" in \"%s\"", import->Name, dll_name);
          return 0;
        }
        printf("Loading \"%s\" from \"%s\"\n", import->Name, dll_name);
      }

      address_table->u1.Function=(uint64_t) fn;
      

      ++lookup_table;
      ++address_table;
    }
    
    ++import_table;
  }  

  return 1;
}

uint8_t pe_relocate_in_mem(const pe_t *self, uint8_t *mem, size_t mem_size){
  if((self->info.optional_header.opt_header64.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) == 0){
    fprintf(stderr, "Cannot relocate pe, missing characteristic\n");
    return 0;
  }
  
  const IMAGE_DATA_DIRECTORY *basereloc = (self->info.is_64bit?
    self->info.optional_header.opt_header64.DataDirectory
    :self->info.optional_header.opt_header32.DataDirectory) + IMAGE_DIRECTORY_ENTRY_BASERELOC;
  
  if(basereloc->VirtualAddress == 0){
    fprintf(stderr, "[pe_relocate_in_mem] Relocation table is empty\n");
    return 1;
  }

  size_t num_relocation_tables = basereloc->Size/IMAGE_SIZEOF_BASE_RELOCATION;
  printf("[pe_relocate_in_mem] basereloc: virtualaddress: %lx size: %lx number of relocation tables: %llu\n", 
          basereloc->VirtualAddress, 
          basereloc->Size, 
          num_relocation_tables);  

  
  int64_t delta = (int64_t) mem - self->info.optional_header.opt_header64.ImageBase;
  printf("[pe_relocate_in_mem] mem: %p (mem) - %llx (imagebase) = %llx (delta)\n",  (void *) mem, self->info.optional_header.opt_header64.ImageBase, delta);
  
  IMAGE_BASE_RELOCATION *relocation_table = (IMAGE_BASE_RELOCATION *) (mem + basereloc->VirtualAddress);
  printf("[pe_relocate_in_mem] basereloc address in image: %p\n", (void *) relocation_table);
   
  while(relocation_table->VirtualAddress){
    printf("relocationtable(%p): VirtualAddress: %lx SizeOfBlock: %lx\n", (void *) relocation_table, relocation_table->VirtualAddress, relocation_table->SizeOfBlock);
    size_t num_relocations = (relocation_table->SizeOfBlock-sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);
    printf("[pe_relocate_in_mem] number of relocations: %llu\n", num_relocations);

    uint16_t *relocation_data=(uint16_t *) &relocation_table[1];
    
    for(size_t i=0;i<num_relocations;++i){
      uint16_t type = relocation_data[i]>>12;
      uint16_t offset = relocation_data[i]&0xfff;
      
      uint8_t **ptr = (uint8_t **) (mem + relocation_table->VirtualAddress + offset);

      if(type == IMAGE_REL_BASED_DIR64){
        printf("[pe_relocate_in_mem] relocate address at %p\n", (void *) ptr);
        if((uint64_t) ptr> (uint64_t) mem+mem_size){
          fprintf(stderr, "ptr: %p is bigger than mem + memsize: %p\n", (void *) ptr, (void *) (mem + mem_size));
        }else{
          *ptr+=delta;
        }
        printf("[pe_relocate_in_mem] relocated\n");
      }
    }
  
  
    relocation_table = (IMAGE_BASE_RELOCATION *)(((uint8_t *) relocation_table) + relocation_table->SizeOfBlock);
  }

  return 1;  
}

uint8_t pe_load_into_memory(const pe_t *self, uint8_t *mem, size_t mem_size) {
  printf("loading aligned into memory...\n");
  if(!pe_load_aligned_into_memory(self, mem, mem_size)){
    return 0;
  }

  printf("loading imports...\n");
  if(!pe_load_imports(self, mem, mem_size)){
    return 0;
  }
  
  printf("relocating in memory...\n");
  if(!pe_relocate_in_mem(self, mem, mem_size)){
    return 0;
  }

  return 1;
}

pe_t *pe_new(const uint8_t *data, size_t data_len){
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
  
  printf("Found PE at %016llx\n", pos);
  pos+=4;
  
  
  memcpy(&self->info.file_header, data+pos, sizeof(IMAGE_FILE_HEADER));
  pos+=sizeof(IMAGE_FILE_HEADER);

  printf("file_header:\n\tSizeOfOptionalHeader: %d\n\
\tNumberOfSections: %d\n\
\tTimeDateStamp: %lu\n\
\tMachine: %d\n", 
    self->info.file_header.SizeOfOptionalHeader,
    self->info.file_header.NumberOfSections,
    self->info.file_header.TimeDateStamp,
    self->info.file_header.Machine
  );

  if((data[pos+1] == 0x01 || data[pos+1] == 0x02) && data[pos] == 0x0b){
    self->info.is_64bit=data[pos+1] == 0x02;
  }else{
    fprintf(stderr, "Opt header magic not found: %02x %02x\n", data[pos], data[pos+1]);
    goto error;
  }
  
  printf("is_opt_header64: %d\n", self->info.is_64bit);

  const size_t opt_header_size = self->info.is_64bit?sizeof(IMAGE_OPTIONAL_HEADER64):sizeof(IMAGE_OPTIONAL_HEADER32);
   
  memcpy(&(self->info.optional_header), data+pos, opt_header_size);

  pos+=opt_header_size;

  printf("read optional header\n");
  self->info.section_table = malloc(sizeof(IMAGE_SECTION_HEADER)*self->info.file_header.NumberOfSections);

  if(self->info.section_table==NULL){
    printf("Failed to allocate section_table\n");
    goto error;
  }
  
  printf("Allocated %d sections\n", self->info.file_header.NumberOfSections);

  if(data_len  < pos+sizeof(IMAGE_SECTION_HEADER)*self->info.file_header.NumberOfSections){
    printf("ERROR: data_len: %llu<%llu", data_len,pos+sizeof(IMAGE_SECTION_HEADER)*self->info.file_header.NumberOfSections );
    goto error;
  }

  printf("section_header start: %llx\n", pos);

  printf("data_len: %llu\n", data_len);
  for(size_t i=0;i<self->info.file_header.NumberOfSections;++i){
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
