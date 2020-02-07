#!/bin/bash

#clear everything from previous runs
rm gdb_output.log > /dev/null 2>&1
rm gdb_output2.log > /dev/null 2>&1
rm gdbcommands > /dev/null 2>&1

#create the assembly file (we actually don't need it)
gcc -S shellcode-creator.c -o shellcode.s -O0 -fno-stack-protector -g

#create the 'shellcode' executable
gcc  shellcode-creator.c -o shellcode -O0 -fno-stack-protector -g

#run gdb to look at the addresses
echo -e "disass main\nq" >> gdbcommands
gdb ./shellcode -q -x gdbcommands > gdb_output.log
#gdb ./shellcode -q -x gdbcommands 
rm gdbcommands

#get the adress of the first of our own instructions 
LINENR=$(grep '<+4>' gdb_output.log | head -1 | sed -e 's/^[ \t]*//'| sed 's/ .*//')
LASTLINENR=$(grep 'retq' gdb_output.log| head -1 | sed -e 's/^[ \t]*//'| sed 's/ .*//')
LASTLINENR=$(printf "%d\n" $(($LASTLINENR - 0x06 )))
LINES=$(printf "%d\n" $(($LASTLINENR - $LINENR )))

#printf "From 0x%X to 0x%X\n" $LINENR $LASTLINENR
#echo $LINES

#run gdb again and get the hex commands for the assembly instructions
echo -e "x/"$LINES"xb "$LINENR" \nq\n" >> gdbcommands
gdb ./shellcode -q -x gdbcommands > gdb_output2.log
#gdb ./shellcode -q -x gdbcommands 
rm gdbcommands

#reformat and strip the output to remove line numbers, spaces etc. and only present the commands in the format \xA1
tail -n+2 gdb_output2.log | sed -n '/<main+/p'  | grep -o '[^:]*$' | sed -e 's/^[ \t]*//' | sed 's/0x/\\x/g' | sed "s/[[:space:]]\+//g" | tr -d '\n' > output.txt

cat output.txt
echo ""
if grep -q "\x00" output.txt; then
    echo -e "\nWARNING: There are still \\\x00 (null bytes) in this shellcode"
fi

#just to be sure, remove everything again
rm gdb_output.log > /dev/null 2>&1
rm gdb_output2.log > /dev/null 2>&1
rm gdbcommands > /dev/null 2>&1
rm shellcode.s  > /dev/null 2>&1
rm shellcode  > /dev/null 2>&1
rm output.txt 
