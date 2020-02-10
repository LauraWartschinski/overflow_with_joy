#!/bin/bash
sudo sysctl -w kernel.randomize_va_space=0


gcc  shellcode-creator.c -o shellcode -O0 -fno-stack-protector -g

gcc hackme1.c -o hackme1 -O0 -fno-stack-protector -z execstack -g 
gcc hackme2.c -o hackme2 -O0 -fno-stack-protector -z execstack -g 
gcc hackme3.c -o hackme3 -O0 -fno-stack-protector -z execstack -g 
gcc hackme4.c -o hackme4 -O0 -fno-stack-protector -z execstack -g 
gcc hackme5.c -o hackme5 -O0 -fno-stack-protector -z execstack -g 
gcc hackme6.c -o hackme6 -O0 -fno-stack-protector -z execstack -g 


gcc exploit1.c -o exploit2 -O0 -fno-stack-protector -z execstack -g
gcc exploit2.c -o exploit2 -O0 -fno-stack-protector -z execstack -g
gcc exploit3.c -o exploit3 -O0 -fno-stack-protector -z execstack -g
gcc exploit4.c -o exploit4 -O0 -fno-stack-protector -z execstack -g
gcc exploit5.c -o exploit5 -O0 -fno-stack-protector -z execstack -g
gcc exploit6.c -o exploit6 -O0 -fno-stack-protector -z execstack -g

