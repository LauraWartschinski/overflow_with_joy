#include <string.h>

void insecure(char* input){
  char buf[8];
  strcpy(buf,input);
  return;
}

int main(int argc, char *argv[])
{
  insecure(argv[1]);
  return 0;
}

