#include<stdio.h>
#include<string.h>
int main(int argc, char *argv[])
{
  char buf[256];
	if (argc < 2)
		puts("Please enter your name as a command line parameter.");
	else
  {
    strcpy(buf,argv[1]);
    printf("Input was: %s\n",buf);
  }
  return 0;
}
