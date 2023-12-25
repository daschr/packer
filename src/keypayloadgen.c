#include <bits/floatn-common.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <time.h>
#include <stdint.h>
#include <string.h>

uint8_t store_key(const uint8_t *key, size_t key_len, const char *out_file){
  #define HEADER "#ifndef _INC_KEY\n#define _INC_KEY\n#include <stdlib.h>\n#include <stdint.h>\nconst uint8_t key[]={"
  #define TRAILER "const size_t key_len=sizeof(key)/sizeof(uint8_t);\n#endif\n"
  const size_t header_len = strlen(HEADER);
  const size_t trailer_len = strlen(TRAILER);

  char *key_payload=NULL;
  FILE *fd = fopen(out_file, "wb");
  if(fd == NULL){
    fprintf(stderr, "Failed to open \"%s\" for writing\n", out_file);
    goto error;
  }
  
  if((key_payload = malloc(sizeof(char)*key_len*6)) == NULL){
    fprintf(stderr, "Failed to allocate memory for the key payload\n");
    goto error;
  }
  
  if(fwrite(HEADER, 1, header_len, fd) != header_len){
    fprintf(stderr, "Failed to write header to \"%s\"\n", out_file);
    goto error;
  }
  
  size_t written =0;

  for(size_t i=0;i<key_len-1;++i){
    written+=sprintf(key_payload+written, "0x%02hhx,", key[i]);
  }
  written+=sprintf(key_payload+written, "0x%02hhx};\n", key[key_len-1]);

  if(fwrite(key_payload, 1, written, fd)!=written){
    fprintf(stderr, "Failed to write key payload to \"%s\"\n", out_file);
    goto error;
  }
  
  free(key_payload);
  
  if(fwrite(TRAILER, 1, trailer_len, fd) != trailer_len){
    fprintf(stderr, "Failed to write trailer to \"%s\"\n", out_file);
    goto error;
  }

  fflush(fd);
  fclose(fd);
  
  return 1;
  #undef HEADER
  #undef TRAILER

error:
  fclose(fd);
  free(key_payload);
  return 0;
}

uint8_t store_payload(const char *in_file, const uint8_t *key, size_t key_len, const char *out_file){
  FILE *in_fd = fopen(in_file, "rb"),  *out_fd = fopen(out_file, "wb");
  if(in_fd == NULL || out_fd == NULL){
    fprintf(stderr, "Failed to open files\n");
    goto error;
  } 

  #define HEADER "#ifndef _INC_HEADER\n#define _INC_HEADER\n#include <stdlib.h>\n#include <stdint.h>\nuint8_t payload[]={"
  #define TRAILER "size_t payload_len=sizeof(payload)/sizeof(uint8_t);\n#endif"
  const size_t header_len = strlen(HEADER);
  const size_t trailer_len = strlen(TRAILER);

  fseek(in_fd, 0, SEEK_END);
  size_t in_size = ftell(in_fd);
  fseek(in_fd, 0, SEEK_SET);

  if(fwrite(HEADER, 1, strlen(HEADER), out_fd) != header_len){
    fprintf(stderr, "Failed to write header to \"%s\"\n", out_file);
    goto error;
  }

  size_t km = key_len-1;
  uint8_t buf;
  in_size-=1;
  size_t i;
  for(i=0;i<in_size;++i){
    if(fread(&buf, 1, 1, in_fd)!=1){
      fprintf(stderr, "Failed to read %luth byte from \"%s\"\n", i+1, in_file);
      goto error;
    }

    if(fprintf(out_fd, "0x%02hhx,",  (uint8_t) (buf^key[i&km])) != 5) {
      fprintf(stderr, "Failed to write %luth byte (as hex) to \"%s\"\n", i+1, out_file);
      goto error;
    }
  }
  ++in_size;

  if(fread(&buf, 1, 1, in_fd) != 1) {
    fprintf(stderr, "Failed to read last byte from \"%s\"\n", in_file);
    goto error;
  }

  if(fprintf(out_fd, "0x%02hhx};\n", (uint8_t) (buf^key[i&km])) != 7){
    fprintf(stderr, "Failed to write last byte (as hex) to \"%s\"\n", out_file);
    goto error;   
  }

  if(fwrite(TRAILER, 1, strlen(TRAILER), out_fd) != trailer_len){
    fprintf(stderr, "Failed to write trailer to \"%s\"\n", out_file);
    goto error;
  }
  
  fflush(out_fd);

  fclose(in_fd);
  fclose(out_fd);
  
  return 1;

  #undef HEADER
  #undef TRAILER

error:
  fclose(in_fd);
  fclose(out_fd);

  return 0;
}

uint8_t *generate_key(size_t len) {
  uint8_t *key = malloc(len * sizeof(uint8_t));
  if(key == NULL) {
    return NULL;
  }

  srand(time(NULL));

  for(size_t i=0;i<len;++i){
    key[i]=rand()&0xff;
  }

   return key; 
}

int main(int ac, char *as[]){
  if(ac != 5) {
    fprintf(stderr, "Usage: %s [IN file] [key length] [OUT key] [OUT payload]\n", as[0]);
    return  1;
  }

  uint32_t key_len;
  if(sscanf(as[2], "%u", &key_len)!=1) {
    fprintf(stderr, "\"%s\" is not a non-negative number!\n", as[2]);
    return 0;
  }
  
  if(key_len==0){
    fprintf(stderr, "Key length cannot be zero\n");
    return 0;
  }
  
  if(__builtin_popcount(key_len) != 1){
    key_len = 1<<(31-__builtin_clz(key_len));
  }

  uint8_t *key = generate_key(key_len);
  if(key == NULL) return 1;

  if(!store_key(key, key_len, as[3]))
    return 1;

  if(!store_payload(as[1], key, key_len, as[4]))
    return 1;

  printf("Stored key in \"%s\" and the encrypted file in \"%s\"\n", as[3], as[4]);

  return 0;
}
