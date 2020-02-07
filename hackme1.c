
int main(void)
{
    char shellcode[] = "";
 
    (*(void (*)()) shellcode)();
     
    return 0;
}