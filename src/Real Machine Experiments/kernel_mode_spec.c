#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<assert.h>
#include<string.h>
#include<fcntl.h>
#include<sys/syscall.h>

long fd;
char *buf;

long make_syscall(int condition)
{
   long retval;
   // Flushing buf from cache
   asm volatile(
                "clflush (%0);"
                "mfence;"
                :
                :"r" (buf)
                : "memory"
                );
   
   
   if(condition){
          // The assembly below executes read(fd, buf, 64)
          asm volatile("mov $1, %%rax;"    //SYSCALL write from /usr/include/x86_64-linux-gnu/asm/unistd_64.h
               "mov %1, %%rdi;"
               "mov %2, %%rsi;"
               "mov $64, %%rdx;"
	            "syscall;"
               "mov %%rax, %0;"
               :"=m" (retval)
               :"r" (fd), "r"(buf)
               :"rax", "rdi", "rsi", "rdx", "rcx", "memory"    
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

   buf=malloc(64);
   memset(buf, 0, 64);


   for(int i=1; i<=100; i++){
        long start, end;
        make_syscall(i<=20);
        start = rdt();
        sum += buf[5];
        end = rdt();
        time_array[i] = end - start;
        lseek(fd, 0, SEEK_SET);
   }

   close(fd);

   for(int i=1; i<=100; i++)
         printf("%d:%ld ", i, time_array[i]);
   printf("\n sum %ld\n", sum);
}