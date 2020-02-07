# overflow_with_joy

## Intro ##

This is a collection of programs written in c that are vulnerable for buffer overflows and exploits.

When programs are executed, they use a stack to store variables, parameters, information about the control flow and so on. For example, when a program enters a function, it has to save the address of the next instruction to execute when it is done with the function and wants to return. 
Some vulnerabilities in code can make it possible to manipulate that stack, e.g. to overwrite the return address, which will cause the programm to jump to a different place in the memory and possibly execute instructions there. Many times, this happens because a buffer - a designated block of memory that stores some values of the same type - is not managed correctly, allowing for values to be written that exceed the capacity of the buffer and overwrite whatever comes next on the stack, possible until the return address (see image below). For a comprehensive introduction into the topic of buffer overflows and executing shell code on the stack, see [smashing the stack for fun and profit](http://www-inst.eecs.berkeley.edu/~cs161/fa08/papers/stack_smashing.pdf).

![Stack](https://github.com/LauraWartschinski/overflow_with_joy/blob/master/img/stack.png)

This repository contains vulnerable c programs and exploits which mostly have the goal to start a shell which will then accept commands to be executed.

## Setup ##
To compile the files with the flags, execute
```./compile-all.sh```
All code is compiled with some flags that make it easier to execute exploits:  `-fno-stack-protector` to not include stack canaries etc., `-z execstack` to make the stack executable, and `-O0` to remove optimizations. All exploits are made to execute on a 64 bit architecture and are tested in Ubuntu 18.04.
This script also disables ASLR (stack randomization), which helps because the memory addresses will stay the same between two executions of the program.


![makeshellcode script](https://github.com/LauraWartschinski/overflow_with_joy/blob/master/img/makeshellcode.png)

There is also a script `makeshellcode.sh`, which will automatically generate the bytes of assembly code for the instructions specified in `shellcode-creator.c`. 

## Hackme 1 ##

## Hackme 2 ##

