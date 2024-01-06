#include <bits/floatn-common.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <time.h>
#include <stdint.h>
#include <string.h>

#define DEFAULT_KEY_NAME "key.h"
#define DEFAULT_PAYLOAD_NAME "payload.h"

uint8_t store_rev_key(const uint8_t *key, size_t key_len, const char *out_file){
  #define HEADER "#ifndef _INC_KEY\n#define _INC_KEY\n#include <stdlib.h>\n#include <stdint.h>\nconst uint8_t key[]={"
  #define TRAILER "const size_t key_len=sizeof(key)/sizeof(uint8_t);\n#endif\n"
  const size_t header_len = strlen(HEADER);
  const size_t trailer_len = strlen(TRAILER);

  char *key_payload=NULL;
  uint8_t *rev_key=NULL;
  
  FILE *fd = fopen(out_file, "wb");
  if(fd == NULL){
    fprintf(stderr, "Failed to open \"%s\" for writing\n", out_file);
    goto error;
  }

  if((rev_key=malloc(sizeof(uint8_t)*key_len))==NULL)
    goto error;
  
  for(size_t i=0;i<256;++i)
    rev_key[key[i]]=(uint8_t) i;
  
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
    written+=sprintf(key_payload+written, "0x%02hhx,", rev_key[i]);
  }
  written+=sprintf(key_payload+written, "0x%02hhx};\n", rev_key[key_len-1]);

  if(fwrite(key_payload, 1, written, fd)!=written){
    fprintf(stderr, "Failed to write key payload to \"%s\"\n", out_file);
    goto error;
  }

  free(rev_key);
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
  free(rev_key);
  return 0;
}

uint8_t store_payload(const char *in_file, const uint8_t *key, const char *out_file){
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

  uint8_t buf;
  in_size-=1;
  size_t i;
  for(i=0;i<in_size;++i){
    if(fread(&buf, 1, 1, in_fd)!=1){
      fprintf(stderr, "Failed to read %luth byte from \"%s\"\n", i+1, in_file);
      goto error;
    }

    if(fprintf(out_fd, "0x%02hhx,",  (uint8_t) (key[buf])) != 5) {
      fprintf(stderr, "Failed to write %luth byte (as hex) to \"%s\"\n", i+1, out_file);
      goto error;
    }
  }
  ++in_size;

  if(fread(&buf, 1, 1, in_fd) != 1) {
    fprintf(stderr, "Failed to read last byte from \"%s\"\n", in_file);
    goto error;
  }

  if(fprintf(out_fd, "0x%02hhx};\n", (uint8_t) (key[buf])) != 7){
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

typedef struct {
  size_t cap;
  size_t len;
  uint8_t *elems;
} list_t;

list_t *list_new(size_t cap){
  list_t *list = malloc(sizeof(list_t));
  if(list == NULL)
    return NULL;
  
  list->cap=cap;
  list->len=0;
  
  list->elems=malloc(sizeof(uint8_t)*cap);
  if(list->elems==NULL){
    free(list);
    return NULL;
  }
  
  return list;
}

uint8_t list_append(list_t *list, uint8_t val){
  if(list->len==list->cap)
    return 0;

  list->elems[list->len++]=val;

  return 1;
}

uint8_t list_remove(list_t *list, size_t pos, uint8_t *out_val) {
  if(pos>=list->len)
    return 0;

  *out_val = list->elems[pos];

  for(size_t i=pos+1;i<list->len;++i)
    list->elems[i-1]=list->elems[i];

  --list->len;

  return 1;
}

void list_free(list_t *list){
  if(list == NULL)
    return;
  
  free(list->elems);
  free(list);
}

uint8_t *generate_key(void) {
  list_t *list = NULL;
  uint8_t *key = NULL;
  
  list = list_new(256);
  if(list == NULL)
    goto error;
  
  for(size_t i=0;i<=255;++i)
    list_append(list, (uint8_t) i);

  key = malloc(256 * sizeof(uint8_t));
  if(key == NULL)
    goto error;
  
  srand(time(NULL));

  uint8_t val;
  for(size_t i=0;i<256;++i){
    if(!list_remove(list, rand()%list->len, &val))
      goto error;
    
    key[i]=val;
  }

  return key; 

error:
  list_free(list);
  free(key);
  
  return NULL;
}

int main(int ac, char *as[]){
  if(ac < 2) {
    fprintf(stderr, "Usage: %s [IN file] [?OUT key] [?OUT payload]\n", as[0]);
    return  1;
  }

  uint8_t *key = generate_key();
  if(key == NULL){
    fprintf(stderr, "Failed to generate key!\n");
    return 1;
  }

  const char *key_outfile = ac > 2?as[2]:DEFAULT_KEY_NAME, *payload_outfile=ac>3?as[3]:DEFAULT_PAYLOAD_NAME;
  
  if(!store_rev_key(key, 256, key_outfile))
    return 1;

  if(!store_payload(as[1], key, payload_outfile))
    return 1;

  printf("Stored key in \"%s\" and the encrypted file in \"%s\"\n", key_outfile, payload_outfile);

  return 0;
}
