CC?=cc
WIN_CC?=x86_64-w64-mingw32-gcc
COMP_ARGS=-Wall -pedantic

all: gen_kp_pair

clean:
	rm -f gen_kp_pair gen_kp_pair.exe packed.exe
	
gen_kp_pair:
	$(CC) $(COMP_ARGS) -o gen_kp_pair src/gen_kp_pair.c


packed_exe: gen_kp_pair payload.h key.h
	$(WIN_CC) $(COMP_ARGS) -I . -o packed src/packer.c src/utils.c
	strip packed.exe
