   #include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<assert.h>
#include<string.h>
#include<fcntl.h>
#include<sys/syscall.h>

long fd;
char *buf;
char *buf2;

long make_syscall(int condition)
{
   long retval;
   asm volatile(
                "clflush (%0);"
                "clflush (%1);"
                "mfence;"
                :
                :"r" (buf), "r" (buf2)
                : "memory"
                );
   if(condition){
          // The assembly below executes read(fd, buf, 64)
          asm volatile("mov $0, %%rax;"    //SYSCALL READ from /usr/include/x86_64-linux-gnu/asm/unistd_64.h
               "mov %1, %%rdi;"
               "mov %2, %%rsi;"
               "mov $64, %%rdx;"
	            "syscall;"
               "mov (%3), %%r9;"
               :"=m" (retval)
               :"r" (fd), "m" (buf), "r" (buf2)
               :"rax", "rdi", "rsi", "rdx", "rcx", "memory", "r9"  
              ); 
   }
   return retval;      
}
long rdt()
{
        unsigned long lo, hi;
        asm volatile( 
             "mfence;"
             "rdtsc;" 
             "mfence;"
             : "=a" (lo), "=d" (hi) 
           ); 
        return( lo | (hi << 32) );
}
int main()
{
   register long sum = 0;
   long time_array[101];
   fd = open("some.txt", O_RDWR|O_CREAT, 0644);
   assert(fd > 0);
   buf=malloc(1 << 30);
   memset(buf, '1', 1 << 30);
   free(buf);
   buf2=malloc(64);
    memset(buf2,0,64);
   buf=malloc(64);
   memset(buf, 0, 64);
   printf("LOOP START\n");
   for(int i=1; i<=100; i++){
        long start, end;
        make_syscall(i<=20);
        start = rdt();
        sum += buf2[5];
        end = rdt();
        time_array[i] = end - start;
        lseek(fd, 0, SEEK_SET);
   }
   close(fd);
   for(int i=1; i<=100; i++)
         printf("%d:%ld ", i, time_array[i]);
   printf("\n sum %ld\n", sum);
}