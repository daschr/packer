#ifndef _INC_UTILS
#define _INC_UTILS

#include <windows.h>
#include <stdint.h>
#include <stdint.h>

typedef struct 
{
	uint16_t signature;
	uint16_t partPag;
	uint16_t pageCnt;
	uint16_t reloCnt;
	uint16_t hdrSize;
	uint16_t minMem;
	uint16_t maxMem;
	uint16_t reloSS;
	uint16_t exeSP;
	uint16_t chksum;
	uint16_t exeIP;
	uint16_t reloCS;
	uint16_t tablOff;
	uint16_t overlay;
	uint8_t reserved[32];
	uint32_t offsetToPE;
} mz_header_t;

typedef struct {
  mz_header_t mz_header;
  IMAGE_FILE_HEADER file_header;
  uint8_t is_64bit;
  size_t end_of_header;
  union {
    IMAGE_OPTIONAL_HEADER32 opt_header32;
    IMAGE_OPTIONAL_HEADER64 opt_header64;
  }  optional_header;
  IMAGE_SECTION_HEADER *section_table;
} pe_info_t;


typedef struct  {
  pe_info_t info;
  const uint8_t *data;
  size_t data_len;
} pe_t;

pe_t *pe_new(const uint8_t *data, size_t data_len);
void pe_free(pe_t *self);
uint8_t pe_load_into_memory(const pe_t *self, uint8_t *mem, size_t mem_size);
size_t pe_get_len(const pe_t *self);

#endif
