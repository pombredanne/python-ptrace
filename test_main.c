#include <string.h>
#include <stdio.h>

void lol(char* str)
{
  char buf[10];

  printf("lol--\n");
  memcpy(buf, str, strlen(str));
  printf("lol++\n");
}

int main()
{
  printf("main--\n");
  lol("abc");
  printf("main++\n");
  return 0;
}
