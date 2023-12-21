#include <stdio.h>
#include <windows.h>

#define EICAR "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

void display_box(const char *title, const char *text) {
  MessageBox(NULL, text, title, MB_OK);
}

int main(int ac, char *as[]){
  puts(EICAR);
  display_box("Message", EICAR);
  
  return 66;
}
