#include <stdio.h>
#include <windows.h>

void display_box(const char *title, const char *text) {
  MessageBox(NULL, text, title, MB_OK);
}

int main(int ac, char *as[]){
  puts("What's up?");
  display_box("Message", ac>1?as[1]:"test 123");
  
  return 66;
}