#!/bin/bash
sudo sysctl -w kernel.randomize_va_space=0


gcc  shellcode-creator.c -o shellcode -O0 -fno-stack-protector -g

gcc hackme1.c -o hackme1 -O0 -fno-stack-protector -z execstack -g 
gcc hackme2.c -o hackme2 -O0 -fno-stack-protector -z execstack -g 


gcc exploit2.c -o exploit2 -O0 -fno-stack-protector -z execstack -g
