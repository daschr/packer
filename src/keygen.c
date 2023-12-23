#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <time.h>
#include <stdint.h>
#include <string.h>

uint8_t gen_key(const char *out, size_t keylen){
  #define HEADER "#ifndef _INC_KEY\n#define _INC_KEY\n#include <stdlib.h>\n#include <stdint.h>\nconst uint8_t key[]={"
  #define TRAILER "const size_t key_len=sizeof(key)/sizeof(uint8_t);\n#endif\n"
  
  FILE *fd = fopen(out, "w");
  if(fd == NULL) return 0;

  srand(time(NULL));

  fwrite(HEADER, 1, strlen(HEADER), fd);

  char *key_payload = malloc(sizeof(char)*keylen*6);
  size_t written =0;

  for(size_t kl=0;kl<keylen-1;++kl){
    written+=sprintf(key_payload+written, "0x%02hhx,", (uint8_t) (rand()&0xff));
  }
  written+=sprintf(key_payload+written, "0x%02hhx};\n", (uint8_t) (rand()&0xff));

  fwrite(key_payload, 1, written, fd);
  free(key_payload);
  
  fwrite(TRAILER, 1, strlen(TRAILER), fd);

  fflush(fd);
  fclose(fd);
  
  return 1;
}

int main(int ac, char *as[]){
  if(ac != 3) {
    fprintf(stderr, "Usage: %s [key] [keylen]\n", as[0]);
    return  1;
  }

  size_t len=0;
  if(sscanf(as[2], "%lu", &len) != 1){
    fprintf(stderr, "Could not parse key length!\n");
    return 1;
  }

  gen_key(as[1], len);
}