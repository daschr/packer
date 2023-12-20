#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <time.h>
#include <stdint.h>
#include <string.h>

#include "key.h"

uint8_t gen_payload(const char *in_file, const char *out_file){
  FILE *in_fd = fopen(in_file, "r"),  *out_fd = fopen(out_file, "w");
  if(in_fd == NULL || out_fd == NULL) return 0;

  #define HEADER "#ifndef _INC_HEADER\n#define _INC_HEADER\n#include <stdlib.h>\n#include <stdint.h>\nuint8_t payload[]={"
  #define TRAILER "size_t payload_len=sizeof(payload)/sizeof(char);\n#endif"

  fseek(in_fd, 0, SEEK_END);
  size_t in_size = ftell(in_fd);
  fseek(in_fd, 0, SEEK_SET);

  fwrite(HEADER, 1, strlen(HEADER), out_fd);

  //printf("key_len: %lu\n", key_len);
  size_t km = key_len-1;
  uint8_t buf;
  in_size-=1;
  size_t i;
  for(i=0;i<in_size;++i){
    fread(&buf, 1, 1, in_fd);
    //printf("Using 0x%02x\n", key[i&km]);
    fprintf(out_fd, "0x%02hhx,",  (uint8_t) (buf^key[i&km]));
  }
  ++in_size;

  fread(&buf, 1, 1, in_fd);

  //printf("Using 0x%02x\n", key[i&km]);
  fprintf(out_fd, "0x%02hhx};\n", (uint8_t) (buf^key[i&km]));

  fwrite(TRAILER, 1, strlen(TRAILER), out_fd);
  
  fflush(out_fd);

  fclose(in_fd);
  fclose(out_fd);
  
  return 1;
}

int main(int ac, char *as[]){
  if(ac != 3) {
    fprintf(stderr, "Usage: %s [in file] [payload file]\n", as[0]);
    return  1;
  }

  gen_payload(as[1], as[2]);
}