# overflow_with_joy

## Intro ##
This is a collection of programs written in c that are vulnerable for buffer overflows, and exploits for them. All are compiled with some flags that make it easier to execute exploits:  `-fno-stack-protector` to not include stack canaries etc., `-z execstack` to make the stack executable, and `-O0` to remove optimizations. All exploits are made to execute on a 64 bit architecture and are tested in Ubuntu 18.04.

## Setup ##
To compile the files with the flags, execute
```./compile-all.sh```
This script also disables ASLR (stack randomization), which helps because the memory addresses will stay the same between two executions of the program.


![makeshellcode script](https://github.com/LauraWartschinski/)

There is also a script `makeshellcode.sh`, which will automatically generate the bytes of assembly code for the instructions specified in `shellcode-creator.c`. 

## Hackme 1 ##

## Hackme 2 ##

