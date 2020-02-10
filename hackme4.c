#include <stdio.h> 
#include <stdlib.h>
#include <string.h> 

//a struct to hold information about a file  
struct file  
{ 
    int id; 
    char filename[8]; 
};

//a struct to hold information about a user
struct user
{
  int id;
  char name[8];
};

  
int main (int argc, char **argv) 
{ 


  if (argc < 2) {
		puts("Please enter your name as a command line parameter.");
    
  } 
  else {

    //creating a user and a file
    struct user *userptr;
    userptr = malloc(sizeof(struct user));

    struct file *fileptr;
    fileptr = malloc(sizeof(struct file));
    fileptr->id = 1;
    strcpy(fileptr->filename, "public.txt");
    
    
    //setting the user information - on the heap, this might overwrite the information of the file
    userptr->id = 1;
    strcpy(userptr->name, argv[1]);
    
    printf("Welcome, user %s!\n\n", userptr->name);
    
    
/*    printf(" [user: %s at %p %p]\n", userptr->name, userptr, userptr->name);
    printf(" [file: %s at %p %p]\n\n", fileptr->filename, fileptr, fileptr->filename);*/
    

    //opening some file, supposedly the file public.txt
    
    printf("On an unrelated note, opening %s.\n", fileptr->filename);
    FILE *readfile;
    readfile = fopen (fileptr->filename, "r"); 
    if (readfile == NULL)     { 
        fprintf(stderr, "Error opening file\n\n"); 
        exit (1); 
    } 


    //printing the file contents
    printf("File was successfully opened. It contains: \n");
    int c;
    while ((c = getc(readfile)) != EOF)
        putchar(c);
    putchar('\n');

  }
  return 0; 
} 
