#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int check_password(char *password){
  int correct = 0;
  char password_buffer[16];
  
  strcpy(password_buffer, password);
  
  if (strcmp(password_buffer, "actualpw") == 0) {
    correct = 1;
  }
  
  return correct;
  
  
}


int main (int argc, char *argv[]) {
  if (argc < 2) {
		puts("Please enter your password as a command line parameter.");
  } else {
    if (check_password(argv[1])) {
      printf("Password correct.\n");
    } else {
      printf("Wrong password.\n");
    }
  }

  return 0;
  
}