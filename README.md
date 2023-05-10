# Documentation
## Reverse Engg. the Speculation around Syscall instruction
We are not sure how the speculation is going on around the syscall instruction. We have 3 possibilities:
1. Instruction just after syscall in user mode execute speculatively(Not Treating Syscall instruction as Branch).
2. Instruction after jumping to trap handler in kernel mode execute speculatively(Treating syscall a branch)
3. Stall the cpu untill the syscall instruction commit and then start executing the kernel mode instruction.(No Speculation going on)

To check which of the three option is implemented in INTEL CPU's, we can design programs such that based on the memory access time we can argue which of the following is implemented.

### Basic Structure of the program
Main Function:
```c
int main()
{
   //Section 1
   register long sum = 0;
   long time_array[101];
   fd = open("some.txt", O_RDWR|O_CREAT, 0644);
   assert(fd > 0);

   //Section 2
   buf=malloc(1 << 30);
   memset(buf, '1', 1 << 30);
   free(buf);

   buf=malloc(64);
   memset(buf, 0, 64);

   //Section 3
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

   //Section 4
   for(int i=1; i<=100; i++)
         printf("%d:%ld ", i, time_array[i]);
   printf("\n sum %ld\n", sum);
}

```
Section 1: Intialising and declaring variables. Opening the file which is used by our syscall.\
Section 2: Cache warming by initialising the large array. Initialising the buffer used by our syscall.\
Section 3: Loop in which we are calling make_syscall function and measuring the time of access of buf[5].\
Section 4: Printing the result of access time.

We will be changing the make_syscall function to deduce the conclusions.

### Kernel Mode Speculation
make_syscall Function:
```c
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
          // The assembly below executes write(fd, buf, 64)
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
```

Firstly we always flush buf from memory. Then depending on the condition(passed as a parameter) we make write syscall. So if condition is true than buf is accessed. 
If the speculation is going on in kernel mode passing the syscall boundary then buf may be accessed due wrong branch prediction(when condition is false) and speculation going far enough such that write to buf is touched.

The output we got is:
```
1:60 2:57 3:58 4:55 5:58 6:56 7:58 8:57 9:55 10:57 11:57 12:57 13:57 14:57 15:59 16:59 17:56 18:58 19:56 20:57 21:235 22:219 23:198 24:213 25:219 26:215 27:217 28:216 29:214 30:215 31:202 32:217 33:213 34:217 35:219 36:213 37:216 38:218 39:197 40:213 41:212 42:215 43:213 44:215 45:217 46:214 47:202 48:213 49:214 50:217 51:727 52:215 53:213 54:214 55:195 56:214 57:214 58:216 59:216 60:216 61:215 62:215 63:194 64:217 65:205 66:217 67:215 68:214 69:214 70:213 71:198 72:211 73:215 74:215 75:215 76:213 77:214 78:215 79:202 80:215 81:632 82:217 83:215 84:217 85:212 86:217 87:202 88:214 89:213 90:214 91:214 92:216 93:215 94:214 95:197 96:212 97:196 98:198 99:254 100:239 
sum 0
```
We can see that after the 20th iteration time goes up means buf is not touched. This indicates that speculation didn't go far enough to touch buf.\
There is a possibility of speculation going on but not touching buf. To test that we modify the entry of syscall to access buf first then do rest of the things

Modified entry_64.S
```
SYM_CODE_START(entry_SYSCALL_64)
	cmpq $780, %rax
	jne label1
	movq (%rsi), %r9
label1:
	UNWIND_HINT_ENTRY
	ENDBR

	swapgs
	/* tss.sp2 is scratch space. */
	movq	%rsp, PER_CPU_VAR(cpu_tss_rw + TSS_sp2)
	SWITCH_TO_KERNEL_CR3 scratch_reg=%rsp
	movq	PER_CPU_VAR(cpu_current_top_of_stack), %rsp

```

Modified make_syscall Function:

```c
long make_syscall(int condition)
{
   long retval;
   asm volatile(
                "clflush (%0);"
                "mfence;"
                :
                :"r" (buf)
                : "memory"
                );
   if(condition){
          // The assembly below executes read(fd, buf, 64)
          asm volatile("mov $780, %%rax;"    //SYSCALL READ from /usr/include/x86_64-linux-gnu/asm/unistd_64.h
               "mov %1, %%rdi;"
               "mov %2, %%rsi;"
               "mov $64, %%rdx;"
               "mov $2432, %%r9;"
	            "syscall;"
               "mov %%rax, %0;"
               :"=m" (retval)
               :"r" (fd), "r"(buf)
               :"rax", "rdi", "rsi", "rdx", "rcx", "memory", "r9"  
              ); 
   }
   return retval;      
}
```
Now we are making call to syscall number 780 which is compared at the time of entry to kernel and buf is accessed even before saving the regs.

The output we got is:
```
1:53 2:51 3:52 4:52 5:55 6:54 7:53 8:52 9:52 10:54 11:55 12:53 13:52 14:55 15:54 16:53 17:53 18:54 19:53 20:54 21:190 22:198 23:193 24:196 25:195 26:194 27:196 28:194 29:194 30:194 31:193 32:195 33:194 34:194 35:191 36:194 37:195 38:196 39:192 40:193 41:190 42:192 43:192 44:195 45:174 46:192 47:193 48:194 49:862 50:194 51:193 52:190 53:174 54:193 55:192 56:193 57:194 58:194 59:193 60:194 61:172 62:192 63:190 64:191 65:192 66:192 67:191 68:192 69:193 70:190 71:194 72:192 73:172 74:192 75:191 76:194 77:191 78:194 79:192 80:816 81:192 82:192 83:195 84:192 85:193 86:192 87:192 88:192 89:55695 90:192 91:176 92:199 93:194 94:179 95:214 96:263 97:247 98:202 99:261 100:237 
sum 0
```
Here we can also see the sudden jump in timing after 20th iteration which means that kernel mode speculation is not going on.

### User Mode Speculation

make_syscall Function is changed to:
```c
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
```
Just after the syscall instruction we are accessing buf2 and we are measuring time of access of buf2 in main. If the user mode speculation is going on then buf2 will be touched when the branch is predicted wrong.

The output we got is:
```
LOOP START
1:58 2:59 3:55 4:55 5:55 6:54 7:53 8:55 9:57 10:55 11:53 12:55 13:55 14:54 15:53 16:56 17:55 18:56 19:55 20:55 21:203 22:219 23:217 24:200 25:210 26:219 27:219 28:223 29:219 30:223 31:219 32:202 33:205 34:685 35:219 36:217 37:221 38:219 39:221 40:215 41:201 42:217 43:216 44:218 45:220 46:222 47:217 48:201 49:219 50:218 51:221 52:221 53:219 54:223 55:221 56:200 57:239 58:217 59:222 60:218 61:222 62:749 63:219 64:220 65:221 66:219 67:222 68:220 69:220 70:215 71:223 72:219 73:201 74:218 75:223 76:220 77:220 78:218 79:218 80:201 81:217 82:220 83:221 84:219 85:219 86:219 87:221 88:202 89:210 90:705 91:219 92:350 93:243 94:255 95:235 96:209 97:203 98:202 99:202 100:224 
sum 0

```
This indicates that User mode speculation is not going.
Then we only left with one option which is that when syscall is encountered, specualtion is stopped.


## Gem5 Experiments
We want to check how syscall is implemented in Gem5.\
So we repeated the experiments in gem5 using the same workload as the real system.\

### Kernel mode speculation
Script used to test kernel mode specualtion:
```py

# Copyright (c) 2021 The Regents of the University of California
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met: redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer;
# redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution;
# neither the name of the copyright holders nor the names of its
# contributors may be used to endorse or promote products derived from
# this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""

This script shows an example of running a full system Ubuntu boot simulation
using the gem5 library. This simulation boots Ubuntu 18.04 using 2 KVM CPU
cores. The simulation then switches to 2 Timing CPU cores before running an
echo statement.

"""

from gem5.utils.requires import requires
from gem5.components.boards.x86_board import X86Board
from gem5.components.memory.single_channel import SingleChannelDDR3_1600
from gem5.components.processors.simple_switchable_processor import (
    SimpleSwitchableProcessor,
)
from gem5.components.processors.cpu_types import CPUTypes
from gem5.isas import ISA
from gem5.coherence_protocol import CoherenceProtocol
from gem5.simulate.simulator import Simulator
from gem5.simulate.exit_event import ExitEvent
from gem5.resources.workload import Workload
from gem5.resources.resource import Resource, CustomDiskImageResource, CustomResource


# This runs a check to ensure the gem5 binary is compiled to X86 and to the
# MESI Two Level coherence protocol.
requires(
    isa_required=ISA.X86,
    coherence_protocol_required=CoherenceProtocol.MESI_TWO_LEVEL,
    kvm_required=True,
)

from gem5.components.cachehierarchies.ruby.mesi_two_level_cache_hierarchy import (
    MESITwoLevelCacheHierarchy,
)

from gem5.components.cachehierarchies.classic.private_l1_shared_l2_cache_hierarchy import PrivateL1SharedL2CacheHierarchy


cache_hierarchy = PrivateL1SharedL2CacheHierarchy(

    l1d_size="32kB",
    l1d_assoc=8,
    l1i_size="32kB",
    l1i_assoc=8,
    l2_size="512kB",
    l2_assoc=16,
)


# Setup the system memory.
memory = SingleChannelDDR3_1600(size="3GB")

# Here we setup the processor. This is a special switchable processor in which
# a starting core type and a switch core type must be specified. Once a
# configuration is instantiated a user may call `processor.switch()` to switch
# from the starting core types to the switch core types. In this simulation
# we start with KVM cores to simulate the OS boot, then switch to the Timing
# cores for the command we wish to run after boot.
processor = SimpleSwitchableProcessor(
    starting_core_type=CPUTypes.KVM,
    switch_core_type=CPUTypes.O3,
    # switch_core_type=CPUTypes.KVM,
    isa=ISA.X86,
    num_cores=1,
)

# Here we setup the board. The X86Board allows for Full-System X86 simulations.
board = X86Board(
    clk_freq="3GHz",
    processor=processor,
    memory=memory,
    cache_hierarchy=cache_hierarchy,
)

# Here we set the Full System workload.
# The `set_kernel_disk_workload` function for the X86Board takes a kernel, a
# disk image, and, optionally, a command to run.

# This is the command to run after the system has booted. The first `m5 exit`
# will stop the simulation so we can switch the CPU cores from KVM to timing
# and continue the simulation to run the echo command, sleep for a second,
# then, again, call `m5 exit` to terminate the simulation. After simulation
# has ended you may inspect `m5out/system.pc.com_1.device` to see the echo
# output.
command = (
    "echo 'This is running on Timing CPU cores.'; ls -l ; touch hello.c; ls -l;"

     + "sleep 1;"
    + "echo " + ''' '
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
   asm volatile(
                "clflush (%0);"
                "mfence;"
                :
                :"r" (buf)
                : "memory"
                );
   if(condition){
          // The assembly below executes read(fd, buf, 64)
          asm volatile("mov $780, %%rax;"    //SYSCALL READ from /usr/include/x86_64-linux-gnu/asm/unistd_64.h
               "mov %1, %%rdi;"
               "mov %2, %%rsi;"
               "mov $64, %%rdx;"
               "mov $2432, %%r9;"
	            "syscall;"
               "mov %%rax, %0;"
               :"=m" (retval)
               :"r" (fd), "r"(buf)
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
   buf=malloc(1 << 25);
   memset(buf, '1', 1 << 25);
   free(buf);
   buf=malloc(64);
   memset(buf, 0, 64);
   printf("LOOP START\\n");
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
   printf("\\n sum %ld\\n", sum);
}

    
    
    
    
    ' ''' +  " > hello.c ;"
    #  + "cat hello.c;"
     + "sudo apt install gcc;"
     + "gcc hello.c;" 
     + "./a.out;"
     +  "m5 exit;"
     + "./a.out;"
     + "echo 'complete';"
    #  + "sleep 1;"s
     + "m5 exit;"
    
)

workload = Workload("x86-ubuntu-18.04-boot")
workload.set_parameter("readfile_contents", command)
workload.set_parameter("kernel",CustomResource("/home/manish/.cache/gem5/nnkernel"))

board.set_workload(workload)



simulator = Simulator(
    board=board,
    on_exit_event={
        # Here we want override the default behavior for the first m5 exit
        # exit event. Instead of exiting the simulator, we just want to
        # switch the processor. The 2nd m5 exit after will revert to using
        # default behavior where the simulator run will exit.
        ExitEvent.EXIT: (func() for func in [processor.switch])
    },
)
simulator.run()

```
Some highlights of Script:
1. Cache used is classic cache not ruby as clflush is only implemented for classic caches and classic cache suffice our purpose for this experiment.
2. Command is run after the system boots up in KVM mode. When first m5 exit is encountered then cpu mode is changed to O3.
3. Kernel is changed with the the kernel which has the changed entry_64.S 

After running this experiment we got the similar output as that of real machine means that kernel mode speculation is not going on in GEM5.
The output we got is:
```
LOOP START
1:55 2:54 3:57 4:55 5:53 6:57 7:53 8:54 9:54 10:55 11:55 12:55 13:53 14:53 15:56 16:55 17:55 18:53 19:55 20:53 21:189 22:184 23:265 24:170 25:210 26:212 27:174 28:173 29:791 30:203 31:174 32:217 33:178 34:178 35:176 36:188 37:207 38:271 39:336 40:220 41:278 42:176 43:194 44:184 45:188 46:177 47:178 48:267 49:211 50:211 51:237 52:390 53:289 54:174 55:184 56:229 57:273 58:213 59:302 60:216 61:265 62:283 63:184 64:180 65:209 66:225 67:208 68:205 69:188 70:177 71:342 72:219 73:220 74:279 75:176 76:183 77:269 78:184 79:180 80:231 81:239 82:210 83:216 84:217 85:202 86:192 87:263 88:225 89:239 90:205 91:176 92:237 93:257 94:206 95:407 96:217 97:255 98:662 99:286 100:275 
 sum 0
LOOP START
1:154 2:33 3:33 4:33 5:33 6:33 7:33 8:33 9:33 10:33 11:33 12:33 13:33 14:33 15:33 16:33 17:33 18:33 19:33 20:33 21:174 22:174 23:174 24:174 25:174 26:999 27:174 28:174 29:174 30:174 31:174 32:174 33:174 34:174 35:174 36:174 37:174 38:174 39:174 40:174 41:174 42:215 43:174 44:174 45:174 46:174 47:174 48:174 49:174 50:174 51:174 52:174 53:174 54:174 55:174 56:174 57:174 58:818 59:174 60:174 61:174 62:174 63:174 64:174 65:174 66:174 67:174 68:174 69:174 70:174 71:174 72:174 73:174 74:215 75:174 76:174 77:174 78:174 79:174 80:174 81:174 82:174 83:174 84:174 85:174 86:174 87:174 88:174 89:174 90:807 91:174 92:174 93:174 94:174 95:174 96:174 97:174 98:174 99:174 100:174 
 sum 0
complete

```

### User Mode Speculation 
The script is changed to run the user mode speculation workload.
The Updated part of the script is:
```py

command = (
    "echo 'This is running on Timing CPU cores.'; ls -l ; touch hello.c; ls -l;"

     + "sleep 1;"
     + "sudo apt install gcc;"
     + "echo " + ''' '   #include<stdio.h>
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
   buf=malloc(1 << 22);
   memset(buf, '1', 1 << 22);
   free(buf);
   buf2=malloc(64);
    memset(buf2,0,64);
   buf=malloc(64);
   memset(buf, 0, 64);
   printf("LOOP START\\n");
   for(int i=1; i<=30; i++){
        long start, end;
        make_syscall(i<=15);
        start = rdt();
        sum += buf2[5];
        end = rdt();
        time_array[i] = end - start;
        lseek(fd, 0, SEEK_SET);
   }
   close(fd);
   for(int i=1; i<=30; i++)
         printf("%d:%ld ", i, time_array[i]);
   printf("\\n sum %ld\\n", sum);
}
' ''' +  " > hello.c ;"
      + "gcc hello.c;" 
     + "./a.out;"
     +  "m5 exit;"
     + "./a.out;"
     + "echo 'complete';"
    #  + "sleep 1;"
     + "m5 exit;"
    
)

```

In this also we saw the similar output as the real system which means the user mode speculation is not happening.
The output we got is:
```
LOOP START
1:77 2:59 3:57 4:55 5:58 6:58 7:58 8:56 9:58 10:54 11:57 12:54 13:54 14:54 15:55 16:221 17:215 18:217 19:304 20:217 21:218 22:216 23:218 24:214 25:221 26:215 27:219 28:235 29:218 30:214 
 sum 0
LOOP START
1:39 2:33 3:33 4:33 5:33 6:33 7:33 8:33 9:33 10:33 11:33 12:33 13:33 14:33 15:33 16:174 17:174 18:174 19:1024 20:174 21:174 22:174 23:174 24:174 25:174 26:174 27:174 28:174 29:174 30:174 
 sum 0
complete
Done running script, exiting.

```

This leave us with the only option possible that is the speculation is turned off in the syscall instruction implementation in Gem5.

## Deep Dive into Syscall instruction in Gem5
Syscall has 25 microops as shown below:
```
Serial No.      Microop                                                                Flags(IsNonSpeculative,IsSerializing,IsSquashAfter)


1.              limm t1, "(uint64_t)(-1)", dataSize=8                                               nnn

                # Save the next RIP.
2.              rdip rcx                                                                            nnn

                # Stick rflags with RF masked into r11.
3.              rflags t2                                                                           nnn

4.              limm t3, "~RFBit", dataSize=8                                                       nnn

5.              and r11, t2, t3, dataSize=8                                                         nnn

6.              rdval t3, star                                                                      nnn

7.              srli t3, t3, 32, dataSize=8                                                         nnn

8.              andi t3, t3, 0xFC, dataSize=1                                                       nnn

                # Set up CS.
9.              wrsel cs, t3                                                                        yyn                

10.             wrbase cs, t0, dataSize=8                                                           yyy

11.             wrlimit cs, t1, dataSize=4                                                          yyy                

                # Not writable, read/execute-able, not expandDown,
                # dpl=0, defaultSize=0, long mode
12.             limm t4, ((0 << 0)  | (0  << 2)  | (0 << 3)   | \
                         (1 << 4)  | (0  << 5)  | (1 << 6)   | \
                         (1 << 7)  | (10 << 8)  | (0 << 12)  | \
                         (1 << 13) | (0  << 14) | (1 << 15)), dataSize=8                            nnn

13.             wrattr cs, t4                                                                       yyy

                # Set up SS.
14.             addi t3, t3, 8                                                                      nnn

15.             wrsel ss, t3                                                                        yyn

16.             wrbase ss, t0, dataSize=8                                                           yyn

17.             wrlimit ss, t1, dataSize=4                                                          yyn

                # Writable, readable, not expandDown,
                # dpl=0, defaultSize=0, not long mode
18.             limm t4, ((0 << 0)  | (0  << 2)  | (1 << 3)   | \
                        (0 << 4)  | (0  << 5)  | (1 << 6)   | \
                        (1 << 7)  | (2  << 8)  | (1 << 12)  | \
                        (1 << 13) | (0  << 14) | (1 << 15)), dataSize=8                             nnn

19.             wrattr ss, t4                                                                       yyn

                # Set the new rip.
20.             rdval t7, lstar, dataSize=8                                                         nnn

21.             wrip t0, t7, dataSize=8

                # Mask the flags against sf_mask and leave RF turned off.
22.             rdval t3, sf_mask, dataSize=8                                                       nnn

23.             xor t3, t3, t1, dataSize=8                                                          nnn

24.             and t3, t3, r11, dataSize=8                                                         nnn

25.             wrflags t3, t0                                                                      yyn

```
y : flag is true \
n : flag is false

Description of the flags:
1. **IsNonSpeculative flag**: If the instruction has non speculative flag true means that when it is issued into the rob its execution only start when it comes to the head of the rob. Instruction after it can exeute freely.
2. **IsSerializeAfter flag**: SerializeAfter marks the next instruction as serializeBefore. SerializeBefore makes the instruction wait in rename until the ROB is empty.
3. **IsSquashAfter flag**: If the instruction has IsSquashAfter flag true means that whenever this instruction come to the head of the ROB all the instruction except this in ROB will be flushed.


## Experimenting with Syscall Instruction in Gem5


### Case 1: Normal Execuation
In the normal execution all the flags of every microops remains what is predefined in the gem5(dyn_inst.hh remains same).   

O3PipeView Utility Output
```
[........fdn.p.ic.r..............................................................]-( 16907516480000) 0x7ffff7a62ba1.1 CMP_R_I                   [  13142906]
[........fdn.p..ic.r.............................................................]-( 16907516480000) 0x7ffff7a62ba8.0 CMOVNBE_R_R               [  13142907]
[........fdn.p...ic.r............................................................]-( 16907516480000) 0x7ffff7a62ba8.1 CMOVNBE_R_R               [  13142908]
[........fdn.ic.....r............................................................]-( 16907516480000) 0x7ffff7a62bac.0 TEST_M_I                  [  13142909]
[.........fdn.ic....r............................................................]-( 16907516480000) 0x7ffff7a62bac.1 TEST_M_I                  [  13142910]
[.........fdn.p.ic..r............................................................]-( 16907516480000) 0x7ffff7a62bac.2 TEST_M_I                  [  13142911]
[.........fdn.ic....r............................................................]-( 16907516480000) 0x7ffff7a62bb3.0 JNZ_I                     [  13142912]
[.........fdn.ic....r............................................................]-( 16907516480000) 0x7ffff7a62bb3.1 JNZ_I                     [  13142913]
[.........fdn.p..ic.r............................................................]-( 16907516480000) 0x7ffff7a62bb3.2 JNZ_I                     [  13142914]
[.........fdn.ic....r............................................................]-( 16907516480000) 0x7ffff7a62bb5.0 MOV_R_M                   [  13142915]
[.........fdn.ic.....r...........................................................]-( 16907516480000) 0x7ffff7a62bbc.0 SUB_M_I                   [  13142916]
[.........fdn.p.ic...r...........................................................]-( 16907516480000) 0x7ffff7a62bbc.1 SUB_M_I                   [  13142917]
[..........fdn.p..ic.r...........................................................]-( 16907516480000) 0x7ffff7a62bbc.2 SUB_M_I                   [  13142918]
[..........fdn.p...ic.r..........................................................]-( 16907516480000) 0x7ffff7a62bbc.3 SUB_M_I                   [  13142919]
[........................fdn.ic.r................................................]-( 16907516480000) 0x7ffff7a62bc0.0 JNZ_I                     [  13142920]
[........................fdn.ic.r................................................]-( 16907516480000) 0x7ffff7a62bc0.1 JNZ_I                     [  13142921]
[........................fdn.pic.r...............................................]-( 16907516480000) 0x7ffff7a62bc0.2 JNZ_I                     [  13142922]
[........................fdn.ic..r...............................................]-( 16907516480000) 0x7ffff7a62bc2.0 MOV_M_I                   [  13142923]
[........................fdn.pic.r...............................................]-( 16907516480000) 0x7ffff7a62bc2.1 MOV_M_I                   [  13142924]
[........................fdn.ic..r...............................................]-( 16907516480000) 0x7ffff7a62bca.0 CMP_P_I                   [  13142925]
[........................fdn.ic..r...............................................]-( 16907516480000) 0x7ffff7a62bca.1 CMP_P_I                   [  13142926]
[........................fdn.pic..r..............................................]-( 16907516480000) 0x7ffff7a62bca.2 CMP_P_I                   [  13142927]
[.........................fdn.p.ic.....r.........................................]-( 16907516480000) 0x7ffff7a62bca.3 CMP_P_I                   [  13142928]
[.........................fdn.ic.......r.........................................]-( 16907516480000) 0x7ffff7a62bd1.0 JZ_I                      [  13142929]
[.........................fdn.ic.......r.........................................]-( 16907516480000) 0x7ffff7a62bd1.1 JZ_I                      [  13142930]
[.........................fdn.p..ic....r.........................................]-( 16907516480000) 0x7ffff7a62bd1.2 JZ_I                      [  13142931]
[.....................................f...dn.ic..r...............................]-( 16907516480000) 0x7ffff7a62bda.0 DEC_M                     [  13142971]
[.....................................f...dn.p.ic..r.............................]-( 16907516480000) 0x7ffff7a62bda.1 DEC_M                     [  13142972]
[.....................................f...dn.p..ic.r.............................]-( 16907516480000) 0x7ffff7a62bda.2 DEC_M                     [  13142973]
[.....................................f...dn.ic....r.............................]-( 16907516480000) 0x7ffff7a62bdc.0 JZ_I                      [  13142974]
[.....................................f...dn.ic....r.............................]-( 16907516480000) 0x7ffff7a62bdc.1 JZ_I                      [  13142975]
[.....................................f...dn.p..ic.r.............................]-( 16907516480000) 0x7ffff7a62bdc.2 JZ_I                      [  13142976]
[...................................................fdn.ic.r.....................]-( 16907516480000) 0x7ffff7a62bf4.0 ADD_R_I                   [  13143014]
[...................................................fdn.pic..r...................]-( 16907516480000) 0x7ffff7a62bf4.1 ADD_R_I                   [  13143015]
[...................................................fdn.ic...r...................]-( 16907516480000) 0x7ffff7a62bf8.0 MOV_R_R                   [  13143016]
[...................................................fdn.p.ic...............r.....]-( 16907516480000) 0x7ffff7a62bfa.0 POP_R                     [  13143017]
[...................................................fdn.p.ic...............r.....]-( 16907516480000) 0x7ffff7a62bfa.1 POP_R                     [  13143018]
[...................................................fdn.p................ic..r...]-( 16907516480000) 0x7ffff7a62bfa.2 POP_R                     [  13143019]
[...................................................fdn.p..ic................r...]-( 16907516480000) 0x7ffff7a62bfb.0 POP_R                     [  13143020]
[...................................................fdn.p..ic................r...]-( 16907516480000) 0x7ffff7a62bfb.1 POP_R                     [  13143021]
[....................................................fdn.p.................ic..r.]-( 16907516480000) 0x7ffff7a62bfb.2 POP_R                     [  13143022]
[....................................................fdn.p..ic.................r.]-( 16907516480000) 0x7ffff7a62bfc.0 POP_R                     [  13143023]
[....................................................fdn.p..ic.................r.]-( 16907516480000) 0x7ffff7a62bfc.1 POP_R                     [  13143024]
[....................................................fdn.p..................ic.r.]-( 16907516480000) 0x7ffff7a62bfc.2 POP_R                     [  13143025]
[....................................................fdn.p...ic................r.]-( 16907516480000) 0x7ffff7a62bfe.0 POP_R                     [  13143026]
[....................................................fdn.p...ic................r.]-( 16907516480000) 0x7ffff7a62bfe.1 POP_R                     [  13143027]
[....................................................fdn.p..................ic.r.]-( 16907516480000) 0x7ffff7a62bfe.2 POP_R                     [  13143028]
[.....................................................fdn.p...ic...............r.]-( 16907516480000) 0x7ffff7a62c00.0 RET_NEAR                  [  13143029]
[.....................................................fdn.p...ic................r]-( 16907516480000) 0x7ffff7a62c00.1 RET_NEAR                  [  13143030]
[.....................................................fdn.p.................ic..r]-( 16907516480000) 0x7ffff7a62c00.2 RET_NEAR                  [  13143031]
[...........................fdn.ic.r.............................................]-( 16907516560000) 0x55555555477d.0 MOV_M_I                   [  13143036]
[...........................fdn.pic.r............................................]-( 16907516560000) 0x55555555477d.1 MOV_M_I                   [  13143037]
[...........................fdn.ic..r............................................]-( 16907516560000) 0x555555554784.0 JMP_I                     [  13143038]
[...........................fdn.ic..r............................................]-( 16907516560000) 0x555555554784.1 JMP_I                     [  13143039]
[...........................fdn.pic.r............................................]-( 16907516560000) 0x555555554784.2 JMP_I                     [  13143040]
[..............................fdn.ic.r..........................................]-( 16907516560000) 0x555555554793.0 CMP_M_I                   [  13143052]
[..............................fdn.ic..r.........................................]-( 16907516560000) 0x555555554793.1 CMP_M_I                   [  13143053]
[..............................fdn.p.ic..r.......................................]-( 16907516560000) 0x555555554793.2 CMP_M_I                   [  13143054]
[..............................fdn.ic....r.......................................]-( 16907516560000) 0x555555554797.0 JLE_I                     [  13143055]
[..............................fdn.ic....r.......................................]-( 16907516560000) 0x555555554797.1 JLE_I                     [  13143056]
[..............................fdn.p..ic.r.......................................]-( 16907516560000) 0x555555554797.2 JLE_I                     [  13143057]
[..........................................fdn.ic.r..............................]-( 16907516560000) 0x555555554786.0 CALL_NEAR_I               [  13143075]
[..........................................fdn.ic.r..............................]-( 16907516560000) 0x555555554786.1 CALL_NEAR_I               [  13143076]
[..........................................fdn.pic.r.............................]-( 16907516560000) 0x555555554786.2 CALL_NEAR_I               [  13143077]
[..........................................fdn.ic..r.............................]-( 16907516560000) 0x555555554786.3 CALL_NEAR_I               [  13143078]
[..........................................fdn.pic.r.............................]-( 16907516560000) 0x555555554786.4 CALL_NEAR_I               [  13143079]
[...........................................................fdn.ic.r.............]-( 16907516560000) 0x5555555546fa.0 PUSH_R                    [  13143086]
[...........................................................fdn.ic.r.............]-( 16907516560000) 0x5555555546fa.1 PUSH_R                    [  13143087]
[...........................................................fdn.pic.r............]-( 16907516560000) 0x5555555546fb.0 MOV_R_R                   [  13143088]
[r........................................................................fdn.ic.]-( 16907516560000) 0x5555555546fe.0 SUB_R_I                   [  13143089]
[.r.......................................................................fdn.pic]-( 16907516560000) 0x5555555546fe.1 SUB_R_I                   [  13143090]
[.r.......................................................................fdn.ic.]-( 16907516560000) 0x555555554702.0 MOV_R_M                   [  13143091]
[c.r......................................................................fdn.p.i]-( 16907516560000) 0x55555555470b.0 MOV_M_R                   [  13143092]
[c.r......................................................................fdn.p.i]-( 16907516560000) 0x55555555470f.0 XOR_R_R                   [  13143093]
[..r......................................................................fdn.ic.]-( 16907516560000) 0x555555554711.0 MOV_R_I                   [  13143094]
[..r......................................................................fdn.ic.]-( 16907516560000) 0x555555554718.0 MOV_R_I                   [  13143095]
[..r......................................................................fdn.ic.]-( 16907516560000) 0x55555555471f.0 SYSCALL_64                [  13143096]
[..r.......................................................................fdn.ic]-( 16907516560000) 0x55555555471f.1 SYSCALL_64                [  13143097]
[ic.r......................................................................fdn.p.]-( 16907516560000) 0x55555555471f.2 SYSCALL_64                [  13143098]
[...r......................................................................fdn.ic]-( 16907516560000) 0x55555555471f.3 SYSCALL_64                [  13143099]
[.ic.r.....................................................................fdn.p.]-( 16907516560000) 0x55555555471f.4 SYSCALL_64                [  13143100]
[....r.....................................................................fdn.ic]-( 16907516560000) 0x55555555471f.5 SYSCALL_64                [  13143101]
[c...r.....................................................................fdn.pi]-( 16907516560000) 0x55555555471f.6 SYSCALL_64                [  13143102]
[ic..r.....................................................................fdn.p.]-( 16907516560000) 0x55555555471f.7 SYSCALL_64                [  13143103]
[.......ic.r...............................................................fdn.p.]-( 16907516560000) 0x55555555471f.8 SYSCALL_64                [  13143104]
[.............p.ic.r........................................................fdn..]-( 16907516560000) 0x55555555471f.9 SYSCALL_64                [  13143105]
[.....................fdn.p.ic.r.................................................]-( 16907516640000) 0x55555555471f.10 SYSCALL_64                [  13143169]
[.................................fdn.ic.r.......................................]-( 16907516640000) 0x55555555471f.11 SYSCALL_64                [  13143232]
[.................................fdn.p.....ic.r.................................]-( 16907516640000) 0x55555555471f.12 SYSCALL_64                [  13143233]
[.................................................fdn.ic.r.......................]-( 16907516640000) 0x55555555471f.13 SYSCALL_64                [  13143294]
[.................................................fdn.p.....ic.r.................]-( 16907516640000) 0x55555555471f.14 SYSCALL_64                [  13143295]
[.................................................fdn.............p.ic.r.........]-( 16907516640000) 0x55555555471f.15 SYSCALL_64                [  13143296]
[.................................................fdn.....................p.ic.r.]-( 16907516640000) 0x55555555471f.16 SYSCALL_64                [  13143297]
[.ic.r............................................fdn............................]-( 16907516640000) 0x55555555471f.17 SYSCALL_64                [  13143298]
[.p.....ic.r......................................fdn............................]-( 16907516640000) 0x55555555471f.18 SYSCALL_64                [  13143299]
[.............ic..r...............................fdn............................]-( 16907516640000) 0x55555555471f.19 SYSCALL_64                [  13143300]
[.............pic.r...............................fdn............................]-( 16907516640000) 0x55555555471f.20 SYSCALL_64                [  13143301]
[..................fdn.ic.r......................................................]-( 16907516720000) 0x55555555471f.21 SYSCALL_64                [  13143354]
[..................fdn.pic.r.....................................................]-( 16907516720000) 0x55555555471f.22 SYSCALL_64                [  13143355]
[..................fdn.p.ic.r....................................................]-( 16907516720000) 0x55555555471f.23 SYSCALL_64                [  13143356]
[..................fdn.p.......ic.r..............................................]-( 16907516720000) 0x55555555471f.24 SYSCALL_64                [  13143357]
[...................fdn..............ic.r........................................]-( 16907516720000) 0xffffffff81600010.0 SWAPGS                    [  13143358]
[...................fdn..............ic.r........................................]-( 16907516720000) 0xffffffff81600010.1 SWAPGS                    [  13143359]
[...................fdn..............p.....ic.r..................................]-( 16907516720000) 0xffffffff81600010.2 SWAPGS                    [  13143360]
[...................fdn..........................p.ic.r..........................]-( 16907516720000) 0xffffffff81600010.3 SWAPGS                    [  13143361]
[...................fdn..................................ic.r....................]-( 16907516720000) 0xffffffff81600013.0 MOV_M_R                   [  13143362]
[...................fdn..................................ic.r....................]-( 16907516720000) 0xffffffff8160001c.0 JMP_I                     [  13143363]
[...................fdn..................................ic.r....................]-( 16907516720000) 0xffffffff8160001c.1 JMP_I                     [  13143364]
[...................fdn..................................pic.r...................]-( 16907516720000) 0xffffffff8160001c.2 JMP_I                     [  13143365]
[....................fdn.................................ic..r...................]-( 16907516720000) 0xffffffff81600030.0 MOV_R_M                   [  13143366]
[....................fdn.................................ic..r...................]-( 16907516720000) 0xffffffff81600039.0 PUSH_I                    [  13143367]
[....................fdn.................................p.ic.r..................]-( 16907516720000) 0xffffffff81600039.1 PUSH_I                    [  13143368]
[....................fdn.................................p.ic.r..................]-( 16907516720000) 0xffffffff81600039.2 PUSH_I                    [  13143369]
[.....................f.................................dn.ic..r.................]-( 16907516720000) 0xffffffff8160003b.0 PUSH_M                    [  13143370]
[.....................f.................................dn.p.ic.r................]-( 16907516720000) 0xffffffff8160003b.1 PUSH_M                    [  13143371]
[.....................f.................................dn.pic..r................]-( 16907516720000) 0xffffffff8160003b.2 PUSH_M                    [  13143372]
[.....................f.................................dn.p.ic.r................]-( 16907516720000) 0xffffffff81600043.0 PUSH_R                    [  13143373]
[.....................f.................................dn.p.ic.r................]-( 16907516720000) 0xffffffff81600043.1 PUSH_R                    [  13143374]
[.....................f.................................dn.ic...r................]-( 16907516720000) 0xffffffff81600045.0 PUSH_I                    [  13143375]
[.....................f.................................dn.p..ic.r...............]-( 16907516720000) 0xffffffff81600045.1 PUSH_I                    [  13143376]
[.....................f.................................dn.p..ic.r...............]-( 16907516720000) 0xffffffff81600045.2 PUSH_I                    [  13143377]
[......................f.................................dn.p..ic.r..............]-( 16907516720000) 0xffffffff81600047.0 PUSH_R                    [  13143378]
[......................f.................................dn.p..ic.r..............]-( 16907516720000) 0xffffffff81600047.1 PUSH_R                    [  13143379]
[......................f.................................dn.p...ic.r.............]-( 16907516720000) 0xffffffff81600048.0 PUSH_R                    [  13143380]
[......................f.................................dn.p...ic.r.............]-( 16907516720000) 0xffffffff81600048.1 PUSH_R                    [  13143381]
[......................f.................................dn.p....ic.r............]-( 16907516720000) 0xffffffff81600049.0 PUSH_R                    [  13143382]
[......................f.................................dn.p....ic.r............]-( 16907516720000) 0xffffffff81600049.1 PUSH_R                    [  13143383]
[......................f.................................dn.p.....ic.r...........]-( 16907516720000) 0xffffffff8160004a.0 PUSH_R                    [  13143384]
[......................f.................................dn.p.....ic.r...........]-( 16907516720000) 0xffffffff8160004a.1 PUSH_R                    [  13143385]
[.......................f..................................dn.p....ic.r..........]-( 16907516720000) 0xffffffff8160004b.0 PUSH_R                    [  13143386]
[.......................f..................................dn.p....ic.r..........]-( 16907516720000) 0xffffffff8160004b.1 PUSH_R                    [  13143387]
[.......................f..................................dn.p.....ic.r.........]-( 16907516720000) 0xffffffff8160004c.0 PUSH_R                    [  13143388]
[.......................f..................................dn.p.....ic.r.........]-( 16907516720000) 0xffffffff8160004c.1 PUSH_R                    [  13143389]
[.......................f..................................dn.ic.......r.........]-( 16907516720000) 0xffffffff8160004d.0 PUSH_I                    [  13143390]
[.......................f..................................dn.p......ic.r........]-( 16907516720000) 0xffffffff8160004d.1 PUSH_I                    [  13143391]
[.......................f..................................dn.p......ic.r........]-( 16907516720000) 0xffffffff8160004d.2 PUSH_I                    [  13143392]

```

Output of printf which we put in dyn_inst.cc to track syscall microops:
```
Count:2200 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : limm   t1, 0xffffffffffffffff Fetch:16907516633000 Decode:16907516634000 Rename:16907516635000 Dispatch: 16907516637000 Issue: 16907516637000 Complete:16907516638000 Commit:16907516642000
 Count:2201 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : rdip   ecx, ecx Fetch:16907516634000 Decode:16907516635000 Rename:16907516636000 Dispatch: 16907516638000 Issue: 16907516638000 Complete:16907516639000 Commit:16907516642000
 Count:2202 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : rflags   t2d, t2d Fetch:16907516634000 Decode:16907516635000 Rename:16907516636000 Dispatch: 16907516638000 Issue: 16907516640000 Complete:16907516641000 Commit:16907516643000
 Count:2203 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : limm   t3, 0xfffffffffffeffff Fetch:16907516634000 Decode:16907516635000 Rename:16907516636000 Dispatch: 16907516638000 Issue: 16907516638000 Complete:16907516639000 Commit:16907516643000
 Count:2204 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : and   r11, t2, t3 Fetch:16907516634000 Decode:16907516635000 Rename:16907516636000 Dispatch: 16907516638000 Issue: 16907516641000 Complete:16907516642000 Commit:16907516644000
 Count:2205 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : rdval   t3d, %ctrl101 Fetch:16907516634000 Decode:16907516635000 Rename:16907516636000 Dispatch: 16907516638000 Issue: 16907516638000 Complete:16907516639000 Commit:16907516644000
 Count:2206 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : srli   t3, t3, 0x20 Fetch:16907516634000 Decode:16907516635000 Rename:16907516636000 Dispatch: 16907516638000 Issue: 16907516639000 Complete:16907516640000 Commit:16907516644000
 Count:2207 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : andi   t3b, t3b, 0xfc Fetch:16907516634000 Decode:16907516635000 Rename:16907516636000 Dispatch: 16907516638000 Issue: 16907516640000 Complete:16907516641000 Commit:16907516644000
 Count:2208 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : wrsel   CS, t3d Fetch:16907516634000 Decode:16907516635000 Rename:16907516636000 Dispatch: 16907516638000 Issue: 16907516647000 Complete:16907516648000 Commit:16907516650000
 Count:2209 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : wrbase   CS, t0 Fetch:16907516635000 Decode:16907516636000 Rename:16907516637000 Dispatch: 16907516653000 Issue: 16907516655000 Complete:16907516656000 Commit:16907516658000
 Count:2210 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : wrlimit   CS, t1d Fetch:16907516661000 Decode:16907516662000 Rename:16907516663000 Dispatch: 16907516665000 Issue: 16907516667000 Complete:16907516668000 Commit:16907516670000
 Count:2211 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : limm   t4, 0xaad0 Fetch:16907516673000 Decode:16907516674000 Rename:16907516675000 Dispatch: 16907516677000 Issue: 16907516677000 Complete:16907516678000 Commit:16907516680000
 Count:2212 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : wrattr   CS, t4d Fetch:16907516673000 Decode:16907516674000 Rename:16907516675000 Dispatch: 16907516677000 Issue: 16907516683000 Complete:16907516684000 Commit:16907516686000
 Count:2213 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : addi   t3d, t3d, 0x8 Fetch:16907516689000 Decode:16907516690000 Rename:16907516691000 Dispatch: 16907516693000 Issue: 16907516693000 Complete:16907516694000 Commit:16907516696000
 Count:2214 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : wrsel   SS, t3d Fetch:16907516689000 Decode:16907516690000 Rename:16907516691000 Dispatch: 16907516693000 Issue: 16907516699000 Complete:16907516700000 Commit:16907516702000
 Count:2215 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : wrbase   SS, t0 Fetch:16907516689000 Decode:16907516690000 Rename:16907516691000 Dispatch: 16907516705000 Issue: 16907516707000 Complete:16907516708000 Commit:16907516710000
 Count:2216 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : wrlimit   SS, t1d Fetch:16907516689000 Decode:16907516690000 Rename:16907516691000 Dispatch: 16907516713000 Issue: 16907516715000 Complete:16907516716000 Commit:16907516718000
 Count:2217 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : limm   t4, 0xb2c8 Fetch:16907516689000 Decode:16907516690000 Rename:16907516691000 Dispatch: 16907516721000 Issue: 16907516721000 Complete:16907516722000 Commit:16907516724000
 Count:2218 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : wrattr   SS, t4d Fetch:16907516689000 Decode:16907516690000 Rename:16907516691000 Dispatch: 16907516721000 Issue: 16907516727000 Complete:16907516728000 Commit:16907516730000
 Count:2219 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : rdval   t7, %ctrl102 Fetch:16907516689000 Decode:16907516690000 Rename:16907516691000 Dispatch: 16907516733000 Issue: 16907516733000 Complete:16907516734000 Commit:16907516737000
 Count:2220 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : wrip   t0, t7 Fetch:16907516689000 Decode:16907516690000 Rename:16907516691000 Dispatch: 16907516733000 Issue: 16907516734000 Complete:16907516735000 Commit:16907516737000
 Count:2221 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : rdval   t3, %ctrl104 Fetch:16907516738000 Decode:16907516739000 Rename:16907516740000 Dispatch: 16907516742000 Issue: 16907516742000 Complete:16907516743000 Commit:16907516745000
 Count:2222 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : xor   t3, t3, t1 Fetch:16907516738000 Decode:16907516739000 Rename:16907516740000 Dispatch: 16907516742000 Issue: 16907516743000 Complete:16907516744000 Commit:16907516746000
 Count:2223 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : and   t3, t3, r11 Fetch:16907516738000 Decode:16907516739000 Rename:16907516740000 Dispatch: 16907516742000 Issue: 16907516744000 Complete:16907516745000 Commit:16907516747000
 Count:2224 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : wrflags   t3d, t0d Fetch:16907516738000 Decode:16907516739000 Rename:16907516740000 Dispatch: 16907516742000 Issue: 16907516750000 Complete:16907516751000 Commit:16907516753000

```

Key Points to note from above Output:
1. Total execution time for syscall insts which we define as (Last microop commit - First Mircoop commit) is 111 cycles
2. wrsel is a non speculative instruction which means its execution cannot start untill it comes to the ROB head which can be seen in the output above. 
3. Squash after flag in wrbase,wrlimit ans wrattr make userbase instruction and kernel instruction separation in the ROB.
4. Specution is correctly going on as expected for microop wrip. When it get decoded we know the branch addr and we can start fetching from that addr now. 
5. We can also see the effect of IsSerializable flag for wrsel, wrbase, wrlimit and wrattr instruction on SS reg.  

### Case 2: Flag IsNonSpeculative and IsSerializeAfter are false for all mircoops of our syscall
In this execution we put false for IsNonSpeculative and IsSerializeAfter flags for every microop of our interested syscall(pc = 0x55555555471f).

We changed 4 functions in dyn_inst.hh as follows:
```c++
    bool isSerializing()  const { 
        if(pcState().instAddr()== 0x55555555471f ){
            std::cout<<"Comes here is serializing: "<< staticInst->disassemble(pcState().instAddr()) <<std::endl;
            return false;
        }
        return staticInst->isSerializing(); 
    }
    bool isSerializeBefore() const
    {
        const std::string s = staticInst->disassemble(pcState().instAddr());    
        if(pcState().instAddr()== 0x55555555471f ){
            std::cout<<"Comes here isserialing before: "<< staticInst->disassemble(pcState().instAddr()) <<std::endl;
            return false;
        }
        return staticInst->isSerializeBefore() || status[SerializeBefore];
    }
    bool
    isSerializeAfter() const
    {
        const std::string s = staticInst->disassemble(pcState().instAddr());    
        if(pcState().instAddr()== 0x55555555471f){
            std::cout<<"Comes here isserialing after: "<< staticInst->disassemble(pcState().instAddr()) <<std::endl;
            return false;
        }
        return staticInst->isSerializeAfter() || status[SerializeAfter];
    }

    bool isNonSpeculative() const { 
        const std::string s = staticInst->disassemble(pcState().instAddr());    
        if(pcState().instAddr()== 0x55555555471f){
            std::cout<<"Comes here nonspec: "<< staticInst->disassemble(pcState().instAddr()) <<std::endl;
            return false;
        }
        return staticInst->isNonSpeculative(); }
```

O3PipeView Utility Output:
```
[................................................................fdn.p.ic.r......]-( 17350509840000) 0x7ffff7a62ba1.1 CMP_R_I                   [  13093210]
[................................................................fdn.p..ic.r.....]-( 17350509840000) 0x7ffff7a62ba8.0 CMOVNBE_R_R               [  13093211]
[................................................................fdn.p...ic.r....]-( 17350509840000) 0x7ffff7a62ba8.1 CMOVNBE_R_R               [  13093212]
[................................................................fdn.ic.....r....]-( 17350509840000) 0x7ffff7a62bac.0 TEST_M_I                  [  13093213]
[.................................................................fdn.ic....r....]-( 17350509840000) 0x7ffff7a62bac.1 TEST_M_I                  [  13093214]
[.................................................................fdn.p.ic..r....]-( 17350509840000) 0x7ffff7a62bac.2 TEST_M_I                  [  13093215]
[.................................................................fdn.ic....r....]-( 17350509840000) 0x7ffff7a62bb3.0 JNZ_I                     [  13093216]
[.................................................................fdn.ic....r....]-( 17350509840000) 0x7ffff7a62bb3.1 JNZ_I                     [  13093217]
[.................................................................fdn.p..ic.r....]-( 17350509840000) 0x7ffff7a62bb3.2 JNZ_I                     [  13093218]
[.................................................................fdn.ic....r....]-( 17350509840000) 0x7ffff7a62bb5.0 MOV_R_M                   [  13093219]
[.................................................................fdn.ic.....r...]-( 17350509840000) 0x7ffff7a62bbc.0 SUB_M_I                   [  13093220]
[.................................................................fdn.p.ic...r...]-( 17350509840000) 0x7ffff7a62bbc.1 SUB_M_I                   [  13093221]
[..................................................................fdn.p..ic.r...]-( 17350509840000) 0x7ffff7a62bbc.2 SUB_M_I                   [  13093222]
[..................................................................fdn.p...ic.r..]-( 17350509840000) 0x7ffff7a62bbc.3 SUB_M_I                   [  13093223]
[fdn.ic.r........................................................................]-( 17350509920000) 0x7ffff7a62bc0.0 JNZ_I                     [  13093224]
[fdn.ic.r........................................................................]-( 17350509920000) 0x7ffff7a62bc0.1 JNZ_I                     [  13093225]
[fdn.pic.r.......................................................................]-( 17350509920000) 0x7ffff7a62bc0.2 JNZ_I                     [  13093226]
[fdn.ic..r.......................................................................]-( 17350509920000) 0x7ffff7a62bc2.0 MOV_M_I                   [  13093227]
[fdn.pic.r.......................................................................]-( 17350509920000) 0x7ffff7a62bc2.1 MOV_M_I                   [  13093228]
[fdn.ic..r.......................................................................]-( 17350509920000) 0x7ffff7a62bca.0 CMP_P_I                   [  13093229]
[fdn.ic..r.......................................................................]-( 17350509920000) 0x7ffff7a62bca.1 CMP_P_I                   [  13093230]
[fdn.pic..r......................................................................]-( 17350509920000) 0x7ffff7a62bca.2 CMP_P_I                   [  13093231]
[.fdn.p.ic.....r.................................................................]-( 17350509920000) 0x7ffff7a62bca.3 CMP_P_I                   [  13093232]
[.fdn.ic.......r.................................................................]-( 17350509920000) 0x7ffff7a62bd1.0 JZ_I                      [  13093233]
[.fdn.ic.......r.................................................................]-( 17350509920000) 0x7ffff7a62bd1.1 JZ_I                      [  13093234]
[.fdn.p..ic....r.................................................................]-( 17350509920000) 0x7ffff7a62bd1.2 JZ_I                      [  13093235]
[.............f...dn.ic..r.......................................................]-( 17350509920000) 0x7ffff7a62bda.0 DEC_M                     [  13093275]
[.............f...dn.p.ic..r.....................................................]-( 17350509920000) 0x7ffff7a62bda.1 DEC_M                     [  13093276]
[.............f...dn.p..ic.r.....................................................]-( 17350509920000) 0x7ffff7a62bda.2 DEC_M                     [  13093277]
[.............f...dn.ic....r.....................................................]-( 17350509920000) 0x7ffff7a62bdc.0 JZ_I                      [  13093278]
[.............f...dn.ic....r.....................................................]-( 17350509920000) 0x7ffff7a62bdc.1 JZ_I                      [  13093279]
[.............f...dn.p..ic.r.....................................................]-( 17350509920000) 0x7ffff7a62bdc.2 JZ_I                      [  13093280]
[...........................fdn.ic.r.............................................]-( 17350509920000) 0x7ffff7a62bf4.0 ADD_R_I                   [  13093318]
[...........................fdn.pic..r...........................................]-( 17350509920000) 0x7ffff7a62bf4.1 ADD_R_I                   [  13093319]
[...........................fdn.ic...r...........................................]-( 17350509920000) 0x7ffff7a62bf8.0 MOV_R_R                   [  13093320]
[...........................fdn.p.ic...............r.............................]-( 17350509920000) 0x7ffff7a62bfa.0 POP_R                     [  13093321]
[...........................fdn.p.ic...............r.............................]-( 17350509920000) 0x7ffff7a62bfa.1 POP_R                     [  13093322]
[...........................fdn.p................ic..r...........................]-( 17350509920000) 0x7ffff7a62bfa.2 POP_R                     [  13093323]
[...........................fdn.p..ic................r...........................]-( 17350509920000) 0x7ffff7a62bfb.0 POP_R                     [  13093324]
[...........................fdn.p..ic................r...........................]-( 17350509920000) 0x7ffff7a62bfb.1 POP_R                     [  13093325]
[............................fdn.p.................ic..r.........................]-( 17350509920000) 0x7ffff7a62bfb.2 POP_R                     [  13093326]
[............................fdn.p..ic.................r.........................]-( 17350509920000) 0x7ffff7a62bfc.0 POP_R                     [  13093327]
[............................fdn.p..ic.................r.........................]-( 17350509920000) 0x7ffff7a62bfc.1 POP_R                     [  13093328]
[............................fdn.p..................ic.r.........................]-( 17350509920000) 0x7ffff7a62bfc.2 POP_R                     [  13093329]
[............................fdn.p...ic................r.........................]-( 17350509920000) 0x7ffff7a62bfe.0 POP_R                     [  13093330]
[............................fdn.p...ic................r.........................]-( 17350509920000) 0x7ffff7a62bfe.1 POP_R                     [  13093331]
[............................fdn.p..................ic.r.........................]-( 17350509920000) 0x7ffff7a62bfe.2 POP_R                     [  13093332]
[.............................fdn.p...ic...............r.........................]-( 17350509920000) 0x7ffff7a62c00.0 RET_NEAR                  [  13093333]
[.............................fdn.p...ic................r........................]-( 17350509920000) 0x7ffff7a62c00.1 RET_NEAR                  [  13093334]
[.............................fdn.p.................ic..r........................]-( 17350509920000) 0x7ffff7a62c00.2 RET_NEAR                  [  13093335]
[...fdn.ic.r.....................................................................]-( 17350510000000) 0x55555555477d.0 MOV_M_I                   [  13093340]
[...fdn.pic.r....................................................................]-( 17350510000000) 0x55555555477d.1 MOV_M_I                   [  13093341]
[...fdn.ic..r....................................................................]-( 17350510000000) 0x555555554784.0 JMP_I                     [  13093342]
[...fdn.ic..r....................................................................]-( 17350510000000) 0x555555554784.1 JMP_I                     [  13093343]
[...fdn.pic.r....................................................................]-( 17350510000000) 0x555555554784.2 JMP_I                     [  13093344]
[......fdn.ic.r..................................................................]-( 17350510000000) 0x555555554793.0 CMP_M_I                   [  13093356]
[......fdn.ic..r.................................................................]-( 17350510000000) 0x555555554793.1 CMP_M_I                   [  13093357]
[......fdn.p.ic..r...............................................................]-( 17350510000000) 0x555555554793.2 CMP_M_I                   [  13093358]
[......fdn.ic....r...............................................................]-( 17350510000000) 0x555555554797.0 JLE_I                     [  13093359]
[......fdn.ic....r...............................................................]-( 17350510000000) 0x555555554797.1 JLE_I                     [  13093360]
[......fdn.p..ic.r...............................................................]-( 17350510000000) 0x555555554797.2 JLE_I                     [  13093361]
[..................fdn.ic.r......................................................]-( 17350510000000) 0x555555554786.0 CALL_NEAR_I               [  13093379]
[..................fdn.ic.r......................................................]-( 17350510000000) 0x555555554786.1 CALL_NEAR_I               [  13093380]
[..................fdn.pic.r.....................................................]-( 17350510000000) 0x555555554786.2 CALL_NEAR_I               [  13093381]
[..................fdn.ic..r.....................................................]-( 17350510000000) 0x555555554786.3 CALL_NEAR_I               [  13093382]
[..................fdn.pic.r.....................................................]-( 17350510000000) 0x555555554786.4 CALL_NEAR_I               [  13093383]
[...................................fdn.ic.r.....................................]-( 17350510000000) 0x5555555546fa.0 PUSH_R                    [  13093390]
[...................................fdn.ic.r.....................................]-( 17350510000000) 0x5555555546fa.1 PUSH_R                    [  13093391]
[...................................fdn.pic.r....................................]-( 17350510000000) 0x5555555546fb.0 MOV_R_R                   [  13093392]
[.................................................fdn.ic.r.......................]-( 17350510000000) 0x5555555546fe.0 SUB_R_I                   [  13093393]
[.................................................fdn.pic.r......................]-( 17350510000000) 0x5555555546fe.1 SUB_R_I                   [  13093394]
[.................................................fdn.ic..r......................]-( 17350510000000) 0x555555554702.0 MOV_R_M                   [  13093395]
[.................................................fdn.p.ic.r.....................]-( 17350510000000) 0x55555555470b.0 MOV_M_R                   [  13093396]
[.................................................fdn.p.ic.r.....................]-( 17350510000000) 0x55555555470f.0 XOR_R_R                   [  13093397]
[.................................................fdn.ic...r.....................]-( 17350510000000) 0x555555554711.0 MOV_R_I                   [  13093398]
[.................................................fdn.ic...r.....................]-( 17350510000000) 0x555555554718.0 MOV_R_I                   [  13093399]
[.................................................fdn.ic...r.....................]-( 17350510000000) 0x55555555471f.0 SYSCALL_64                [  13093400]
[..................................................fdn.ic..r.....................]-( 17350510000000) 0x55555555471f.1 SYSCALL_64                [  13093401]
[..................................................fdn.p.ic....r.................]-( 17350510000000) 0x55555555471f.2 SYSCALL_64                [  13093402]
[..................................................fdn.ic......r.................]-( 17350510000000) 0x55555555471f.3 SYSCALL_64                [  13093403]
[..................................................fdn.p..ic...r.................]-( 17350510000000) 0x55555555471f.4 SYSCALL_64                [  13093404]
[..................................................fdn.ic......r.................]-( 17350510000000) 0x55555555471f.5 SYSCALL_64                [  13093405]
[..................................................fdn.pic.....r.................]-( 17350510000000) 0x55555555471f.6 SYSCALL_64                [  13093406]
[..................................................fdn.p.ic....r.................]-( 17350510000000) 0x55555555471f.7 SYSCALL_64                [  13093407]
[..................................................fdn.p..ic...r.................]-( 17350510000000) 0x55555555471f.8 SYSCALL_64                [  13093408]
[...................................................fdn.ic.....r.................]-( 17350510000000) 0x55555555471f.9 SYSCALL_64                [  13093409]
[.................................................................fdn...ic.r.....]-( 17350510000000) 0x55555555471f.10 SYSCALL_64                [  13093450]
[.ic.r........................................................................fdn]-( 17350510000000) 0x55555555471f.11 SYSCALL_64                [  13093466]
[.pic..r......................................................................fdn]-( 17350510000000) 0x55555555471f.12 SYSCALL_64                [  13093467]
[.........fdn.ic.r...............................................................]-( 17350510080000) 0x55555555471f.13 SYSCALL_64                [  13093481]
[.........fdn.pic.r..............................................................]-( 17350510080000) 0x55555555471f.14 SYSCALL_64                [  13093482]
[.........fdn.ic..r..............................................................]-( 17350510080000) 0x55555555471f.15 SYSCALL_64                [  13093483]
[.........fdn.ic..r..............................................................]-( 17350510080000) 0x55555555471f.16 SYSCALL_64                [  13093484]
[.........fdn.ic..r..............................................................]-( 17350510080000) 0x55555555471f.17 SYSCALL_64                [  13093485]
[.........fdn.pic.r..............................................................]-( 17350510080000) 0x55555555471f.18 SYSCALL_64                [  13093486]
[.........fdn.ic..r..............................................................]-( 17350510080000) 0x55555555471f.19 SYSCALL_64                [  13093487]
[.........fdn.pic.r..............................................................]-( 17350510080000) 0x55555555471f.20 SYSCALL_64                [  13093488]
[..........f.dn.ic.r.............................................................]-( 17350510080000) 0x55555555471f.21 SYSCALL_64                [  13093489]
[..........f.dn.pic.r............................................................]-( 17350510080000) 0x55555555471f.22 SYSCALL_64                [  13093490]
[..........f.dn.p.ic.r...........................................................]-( 17350510080000) 0x55555555471f.23 SYSCALL_64                [  13093491]
[..........f.dn.p..ic.r..........................................................]-( 17350510080000) 0x55555555471f.24 SYSCALL_64                [  13093492]
[...........f.dn.ic...r..........................................................]-( 17350510080000) 0xffffffff81600010.0 SWAPGS                    [  13093493]
[...........f.dn.ic...r..........................................................]-( 17350510080000) 0xffffffff81600010.1 SWAPGS                    [  13093494]
[...........f.dn.p.......ic.r....................................................]-( 17350510080000) 0xffffffff81600010.2 SWAPGS                    [  13093495]
[...........f.dn...............p.ic.r............................................]-( 17350510080000) 0xffffffff81600010.3 SWAPGS                    [  13093496]
[...........f.dn.......................ic.r......................................]-( 17350510080000) 0xffffffff81600013.0 MOV_M_R                   [  13093497]
[...........f.dn.......................ic.r......................................]-( 17350510080000) 0xffffffff8160001c.0 JMP_I                     [  13093498]
[...........f.dn.......................ic.r......................................]-( 17350510080000) 0xffffffff8160001c.1 JMP_I                     [  13093499]
[...........f.dn.......................pic.r.....................................]-( 17350510080000) 0xffffffff8160001c.2 JMP_I                     [  13093500]
[............f........................dn.ic..r...................................]-( 17350510080000) 0xffffffff81600030.0 MOV_R_M                   [  13093501]
[............f........................dn.ic..r...................................]-( 17350510080000) 0xffffffff81600039.0 PUSH_I                    [  13093502]
[............f........................dn.p.ic.r..................................]-( 17350510080000) 0xffffffff81600039.1 PUSH_I                    [  13093503]
[............f........................dn.p.ic.r..................................]-( 17350510080000) 0xffffffff81600039.2 PUSH_I                    [  13093504]
[.............f.......................dn.ic...r..................................]-( 17350510080000) 0xffffffff8160003b.0 PUSH_M                    [  13093505]
[.............f.......................dn.p..ic.r.................................]-( 17350510080000) 0xffffffff8160003b.1 PUSH_M                    [  13093506]
[.............f.......................dn.p..ic.r.................................]-( 17350510080000) 0xffffffff8160003b.2 PUSH_M                    [  13093507]
[.............f.......................dn.p...ic.r................................]-( 17350510080000) 0xffffffff81600043.0 PUSH_R                    [  13093508]
[.............f........................dn.p..ic.r................................]-( 17350510080000) 0xffffffff81600043.1 PUSH_R                    [  13093509]
[.............f........................dn.ic....r................................]-( 17350510080000) 0xffffffff81600045.0 PUSH_I                    [  13093510]
[.............f........................dn.p...ic.r...............................]-( 17350510080000) 0xffffffff81600045.1 PUSH_I                    [  13093511]
[.............f........................dn.p...ic.r...............................]-( 17350510080000) 0xffffffff81600045.2 PUSH_I                    [  13093512]
[..............f.......................dn.p....ic.r..............................]-( 17350510080000) 0xffffffff81600047.0 PUSH_R                    [  13093513]
[..............f.......................dn.p....ic.r..............................]-( 17350510080000) 0xffffffff81600047.1 PUSH_R                    [  13093514]
[..............f.......................dn.p.....ic.r.............................]-( 17350510080000) 0xffffffff81600048.0 PUSH_R                    [  13093515]
[..............f.......................dn.p.....ic.r.............................]-( 17350510080000) 0xffffffff81600048.1 PUSH_R                    [  13093516]
[..............f.........................dn.p....ic.r............................]-( 17350510080000) 0xffffffff81600049.0 PUSH_R                    [  13093517]
[..............f.........................dn.p....ic.r............................]-( 17350510080000) 0xffffffff81600049.1 PUSH_R                    [  13093518]
[..............f.........................dn.p.....ic.r...........................]-( 17350510080000) 0xffffffff8160004a.0 PUSH_R                    [  13093519]
[..............f.........................dn.p.....ic.r...........................]-( 17350510080000) 0xffffffff8160004a.1 PUSH_R                    [  13093520]
[...............f........................dn.p......ic.r..........................]-( 17350510080000) 0xffffffff8160004b.0 PUSH_R                    [  13093521]
[...............f........................dn.p......ic.r..........................]-( 17350510080000) 0xffffffff8160004b.1 PUSH_R                    [  13093522]
[...............f........................dn.p.......ic.r.........................]-( 17350510080000) 0xffffffff8160004c.0 PUSH_R                    [  13093523]
[...............f........................dn.p.......ic.r.........................]-( 17350510080000) 0xffffffff8160004c.1 PUSH_R                    [  13093524]
[...............f.........................dn.ic........r.........................]-( 17350510080000) 0xffffffff8160004d.0 PUSH_I                    [  13093525]
[...............f.........................dn.p.......ic.r........................]-( 17350510080000) 0xffffffff8160004d.1 PUSH_I                    [  13093526]
[...............f.........................dn.p.......ic.r........................]-( 17350510080000) 0xffffffff8160004d.2 PUSH_I                    [  13093527]
[...............f.........................dn.p........ic.r.......................]-( 17350510080000) 0xffffffff8160004f.0 PUSH_R                    [  13093528]
[................f........................dn.p........ic.r.......................]-( 17350510080000) 0xffffffff8160004f.1 PUSH_R                    [  13093529]
[................f........................dn.p.........ic.r......................]-( 17350510080000) 0xffffffff81600051.0 PUSH_R                    [  13093530]

```
Output of printf which we put in dyn_inst.cc to track syscall microops:
```
Count:2025 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : limm   t1, 0xffffffffffffffff Fetch:17350510049000 Decode:17350510050000 Rename:17350510051000 Dispatch: 17350510053000 Issue: 17350510053000 Complete:17350510054000 Commit:17350510058000
 Count:2026 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : rdip   ecx, ecx Fetch:17350510050000 Decode:17350510051000 Rename:17350510052000 Dispatch: 17350510054000 Issue: 17350510054000 Complete:17350510055000 Commit:17350510058000
Count:2027 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : rflags   t2d, t2d Fetch:17350510050000 Decode:17350510051000 Rename:17350510052000 Dispatch: 17350510054000 Issue: 17350510056000 Complete:17350510057000 Commit:17350510062000
 Count:2028 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : limm   t3, 0xfffffffffffeffff Fetch:17350510050000 Decode:17350510051000 Rename:17350510052000 Dispatch: 17350510054000 Issue: 17350510054000 Complete:17350510055000 Commit:17350510062000
 Count:2029 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : and   r11, t2, t3 Fetch:17350510050000 Decode:17350510051000 Rename:17350510052000 Dispatch: 17350510054000 Issue: 17350510057000 Complete:17350510058000 Commit:17350510062000
 Count:2030 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : rdval   t3d, %ctrl101 Fetch:17350510050000 Decode:17350510051000 Rename:17350510052000 Dispatch: 17350510054000 Issue: 17350510054000 Complete:17350510055000 Commit:17350510062000
 Count:2031 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : srli   t3, t3, 0x20 Fetch:17350510050000 Decode:17350510051000 Rename:17350510052000 Dispatch: 17350510054000 Issue: 17350510055000 Complete:17350510056000 Commit:17350510062000
 Count:2032 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : andi   t3b, t3b, 0xfc Fetch:17350510050000 Decode:17350510051000 Rename:17350510052000 Dispatch: 17350510054000 Issue: 17350510056000 Complete:17350510057000 Commit:17350510062000
 Count:2033 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : wrsel   CS, t3d Fetch:17350510050000 Decode:17350510051000 Rename:17350510052000 Dispatch: 17350510054000 Issue: 17350510057000 Complete:17350510058000 Commit:17350510062000
 Count:2034 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : wrbase   CS, t0 Fetch:17350510051000 Decode:17350510052000 Rename:17350510053000 Dispatch: 17350510055000 Issue: 17350510055000 Complete:17350510056000 Commit:17350510062000
Count:2035 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : wrlimit   CS, t1d Fetch:17350510065000 Decode:17350510066000 Rename:17350510067000 Dispatch: 17350510071000 Issue: 17350510071000 Complete:17350510072000 Commit:17350510074000
Count:2036 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : limm   t4, 0xaad0 Fetch:17350510077000 Decode:17350510078000 Rename:17350510079000 Dispatch: 17350510081000 Issue: 17350510081000 Complete:17350510082000 Commit:17350510084000
 Count:2037 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : wrattr   CS, t4d Fetch:17350510077000 Decode:17350510078000 Rename:17350510079000 Dispatch: 17350510081000 Issue: 17350510082000 Complete:17350510083000 Commit:17350510086000
Count:2038 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : addi   t3d, t3d, 0x8 Fetch:17350510089000 Decode:17350510090000 Rename:17350510091000 Dispatch: 17350510093000 Issue: 17350510093000 Complete:17350510094000 Commit:17350510096000
 Count:2039 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : wrsel   SS, t3d Fetch:17350510089000 Decode:17350510090000 Rename:17350510091000 Dispatch: 17350510093000 Issue: 17350510094000 Complete:17350510095000 Commit:17350510097000
 Count:2040 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : wrbase   SS, t0 Fetch:17350510089000 Decode:17350510090000 Rename:17350510091000 Dispatch: 17350510093000 Issue: 17350510093000 Complete:17350510094000 Commit:17350510097000
 Count:2041 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : wrlimit   SS, t1d Fetch:17350510089000 Decode:17350510090000 Rename:17350510091000 Dispatch: 17350510093000 Issue: 17350510093000 Complete:17350510094000 Commit:17350510097000
 Count:2042 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : limm   t4, 0xb2c8 Fetch:17350510089000 Decode:17350510090000 Rename:17350510091000 Dispatch: 17350510093000 Issue: 17350510093000 Complete:17350510094000 Commit:17350510097000
 Count:2043 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : wrattr   SS, t4d Fetch:17350510089000 Decode:17350510090000 Rename:17350510091000 Dispatch: 17350510093000 Issue: 17350510094000 Complete:17350510095000 Commit:17350510097000
 Count:2044 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : rdval   t7, %ctrl102 Fetch:17350510089000 Decode:17350510090000 Rename:17350510091000 Dispatch: 17350510093000 Issue: 17350510093000 Complete:17350510094000 Commit:17350510097000
 Count:2045 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : wrip   t0, t7 Fetch:17350510089000 Decode:17350510090000 Rename:17350510091000 Dispatch: 17350510093000 Issue: 17350510094000 Complete:17350510095000 Commit:17350510097000
 Count:2046 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : rdval   t3, %ctrl104 Fetch:17350510090000 Decode:17350510092000 Rename:17350510093000 Dispatch: 17350510095000 Issue: 17350510095000 Complete:17350510096000 Commit:17350510098000
 Count:2047 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : xor   t3, t3, t1 Fetch:17350510090000 Decode:17350510092000 Rename:17350510093000 Dispatch: 17350510095000 Issue: 17350510096000 Complete:17350510097000 Commit:17350510099000
 Count:2048 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : and   t3, t3, r11 Fetch:17350510090000 Decode:17350510092000 Rename:17350510093000 Dispatch: 17350510095000 Issue: 17350510097000 Complete:17350510098000 Commit:17350510100000
 Count:2049 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : wrflags   t3d, t0d Fetch:17350510090000 Decode:17350510092000 Rename:17350510093000 Dispatch: 17350510095000 Issue: 17350510098000 Complete:17350510099000 Commit:17350510101000

```

Key Observations to note:
1. Total execution time becomes 43 cycles.
2. Now we are only loosing out the pipelining effect on wrbase,wrlimit and wrattr for which we are sqaushing the ROB(can be seen from the O3PipeView utility output).


### Case 3: Flag IsNonSpeculative, IsSerializeAfter and IsSquashAfter are false for all microops except wrattr microop for which IsSquashAfter flag is true for our syscall
In this case we put false for flags IsNonSpeculative, IsSerializeAfter and IsSquashAfter for every microop except wattr for which the the flag IsSquashAfter remains true to separate the usermode and kernel mode instruction and CS reg is written by wrsel, wrbase, wrlimit and wrattr. All instructions have an internel dependency to CS reg. So no kernel instruction should be executed untill the CS reg is changed(priviledge change) which is achieved by keeping the IsSquahAfter Flag for the last microop which changes the priviledge.

We changed 5 functions in dyn_inst.hh as follows:
```c++
    bool isSerializing()  const { 
        if(pcState().instAddr()== 0x55555555471f ){
            std::cout<<"Comes here is serializing: "<< staticInst->disassemble(pcState().instAddr()) <<std::endl;
            return false;
        }
        return staticInst->isSerializing(); 
    }
    bool isSerializeBefore() const
    {
        const std::string s = staticInst->disassemble(pcState().instAddr());    
        if(pcState().instAddr()== 0x55555555471f ){
            std::cout<<"Comes here isserialing before: "<< staticInst->disassemble(pcState().instAddr()) <<std::endl;
            return false;
        }
        return staticInst->isSerializeBefore() || status[SerializeBefore];
    }
    bool
    isSerializeAfter() const
    {
        const std::string s = staticInst->disassemble(pcState().instAddr());    
        if(pcState().instAddr()== 0x55555555471f){
            std::cout<<"Comes here isserialing after: "<< staticInst->disassemble(pcState().instAddr()) <<std::endl;
            return false;
        }
        return staticInst->isSerializeAfter() || status[SerializeAfter];
    }

    bool isSquashAfter() const { 
        
        const std::string s = staticInst->disassemble(pcState().instAddr());    
        if(pcState().instAddr()== 0x55555555471f && s.find("SYSCALL_64 : wrattr") == std::string::npos){
            std::cout<<"Comes here squash after: "<< staticInst->disassemble(pcState().instAddr()) <<std::endl;
            return false;
        }

        return staticInst->isSquashAfter();
     }
    
    bool isNonSpeculative() const { 
        const std::string s = staticInst->disassemble(pcState().instAddr());    
        if(pcState().instAddr()== 0x55555555471f){
            std::cout<<"Comes here nonspec: "<< staticInst->disassemble(pcState().instAddr()) <<std::endl;
            return false;
        }
        return staticInst->isNonSpeculative(); }
```


O3PipeView Utility Output:
```
[.............fdn.p.ic.r.........................................................]-( 18501453040000) 0x7ffff7a62ba1.1 CMP_R_I                   [  13411939]
[.............fdn.p..ic.r........................................................]-( 18501453040000) 0x7ffff7a62ba8.0 CMOVNBE_R_R               [  13411940]
[.............fdn.p...ic.r.......................................................]-( 18501453040000) 0x7ffff7a62ba8.1 CMOVNBE_R_R               [  13411941]
[.............fdn.ic.....r.......................................................]-( 18501453040000) 0x7ffff7a62bac.0 TEST_M_I                  [  13411942]
[..............fdn.ic....r.......................................................]-( 18501453040000) 0x7ffff7a62bac.1 TEST_M_I                  [  13411943]
[..............fdn.p.ic..r.......................................................]-( 18501453040000) 0x7ffff7a62bac.2 TEST_M_I                  [  13411944]
[..............fdn.ic....r.......................................................]-( 18501453040000) 0x7ffff7a62bb3.0 JNZ_I                     [  13411945]
[..............fdn.ic....r.......................................................]-( 18501453040000) 0x7ffff7a62bb3.1 JNZ_I                     [  13411946]
[..............fdn.p..ic.r.......................................................]-( 18501453040000) 0x7ffff7a62bb3.2 JNZ_I                     [  13411947]
[..............fdn.ic....r.......................................................]-( 18501453040000) 0x7ffff7a62bb5.0 MOV_R_M                   [  13411948]
[..............fdn.ic.....r......................................................]-( 18501453040000) 0x7ffff7a62bbc.0 SUB_M_I                   [  13411949]
[..............fdn.p.ic...r......................................................]-( 18501453040000) 0x7ffff7a62bbc.1 SUB_M_I                   [  13411950]
[...............fdn.p..ic.r......................................................]-( 18501453040000) 0x7ffff7a62bbc.2 SUB_M_I                   [  13411951]
[...............fdn.p...ic.r.....................................................]-( 18501453040000) 0x7ffff7a62bbc.3 SUB_M_I                   [  13411952]
[.............................fdn.ic.r...........................................]-( 18501453040000) 0x7ffff7a62bc0.0 JNZ_I                     [  13411953]
[.............................fdn.ic.r...........................................]-( 18501453040000) 0x7ffff7a62bc0.1 JNZ_I                     [  13411954]
[.............................fdn.pic.r..........................................]-( 18501453040000) 0x7ffff7a62bc0.2 JNZ_I                     [  13411955]
[.............................fdn.ic..r..........................................]-( 18501453040000) 0x7ffff7a62bc2.0 MOV_M_I                   [  13411956]
[.............................fdn.pic.r..........................................]-( 18501453040000) 0x7ffff7a62bc2.1 MOV_M_I                   [  13411957]
[.............................fdn.ic..r..........................................]-( 18501453040000) 0x7ffff7a62bca.0 CMP_P_I                   [  13411958]
[.............................fdn.ic..r..........................................]-( 18501453040000) 0x7ffff7a62bca.1 CMP_P_I                   [  13411959]
[.............................fdn.pic..r.........................................]-( 18501453040000) 0x7ffff7a62bca.2 CMP_P_I                   [  13411960]
[..............................fdn.p.ic.....r....................................]-( 18501453040000) 0x7ffff7a62bca.3 CMP_P_I                   [  13411961]
[..............................fdn.ic.......r....................................]-( 18501453040000) 0x7ffff7a62bd1.0 JZ_I                      [  13411962]
[..............................fdn.ic.......r....................................]-( 18501453040000) 0x7ffff7a62bd1.1 JZ_I                      [  13411963]
[..............................fdn.p..ic....r....................................]-( 18501453040000) 0x7ffff7a62bd1.2 JZ_I                      [  13411964]
[..........................................f...dn.ic..r..........................]-( 18501453040000) 0x7ffff7a62bda.0 DEC_M                     [  13412004]
[..........................................f...dn.p.ic..r........................]-( 18501453040000) 0x7ffff7a62bda.1 DEC_M                     [  13412005]
[..........................................f...dn.p..ic.r........................]-( 18501453040000) 0x7ffff7a62bda.2 DEC_M                     [  13412006]
[..........................................f...dn.ic....r........................]-( 18501453040000) 0x7ffff7a62bdc.0 JZ_I                      [  13412007]
[..........................................f...dn.ic....r........................]-( 18501453040000) 0x7ffff7a62bdc.1 JZ_I                      [  13412008]
[..........................................f...dn.p..ic.r........................]-( 18501453040000) 0x7ffff7a62bdc.2 JZ_I                      [  13412009]
[........................................................fdn.ic.r................]-( 18501453040000) 0x7ffff7a62bf4.0 ADD_R_I                   [  13412047]
[........................................................fdn.pic..r..............]-( 18501453040000) 0x7ffff7a62bf4.1 ADD_R_I                   [  13412048]
[........................................................fdn.ic...r..............]-( 18501453040000) 0x7ffff7a62bf8.0 MOV_R_R                   [  13412049]
[........................................................fdn.p.ic...............r]-( 18501453040000) 0x7ffff7a62bfa.0 POP_R                     [  13412050]
[........................................................fdn.p.ic...............r]-( 18501453040000) 0x7ffff7a62bfa.1 POP_R                     [  13412051]
[.r......................................................fdn.p................ic.]-( 18501453040000) 0x7ffff7a62bfa.2 POP_R                     [  13412052]
[.r......................................................fdn.p..ic...............]-( 18501453040000) 0x7ffff7a62bfb.0 POP_R                     [  13412053]
[.r......................................................fdn.p..ic...............]-( 18501453040000) 0x7ffff7a62bfb.1 POP_R                     [  13412054]
[c..r.....................................................fdn.p.................i]-( 18501453040000) 0x7ffff7a62bfb.2 POP_R                     [  13412055]
[...r.....................................................fdn.p..ic..............]-( 18501453040000) 0x7ffff7a62bfc.0 POP_R                     [  13412056]
[...r.....................................................fdn.p..ic..............]-( 18501453040000) 0x7ffff7a62bfc.1 POP_R                     [  13412057]
[ic.r.....................................................fdn.p..................]-( 18501453040000) 0x7ffff7a62bfc.2 POP_R                     [  13412058]
[...r.....................................................fdn.p...ic.............]-( 18501453040000) 0x7ffff7a62bfe.0 POP_R                     [  13412059]
[...r.....................................................fdn.p...ic.............]-( 18501453040000) 0x7ffff7a62bfe.1 POP_R                     [  13412060]
[ic.r.....................................................fdn.p..................]-( 18501453040000) 0x7ffff7a62bfe.2 POP_R                     [  13412061]
[...r......................................................fdn.p...ic............]-( 18501453040000) 0x7ffff7a62c00.0 RET_NEAR                  [  13412062]
[....r.....................................................fdn.p...ic............]-( 18501453040000) 0x7ffff7a62c00.1 RET_NEAR                  [  13412063]
[ic..r.....................................................fdn.p.................]-( 18501453040000) 0x7ffff7a62c00.2 RET_NEAR                  [  13412064]
[................................fdn.ic.r........................................]-( 18501453120000) 0x55555555477d.0 MOV_M_I                   [  13412069]
[................................fdn.pic.r.......................................]-( 18501453120000) 0x55555555477d.1 MOV_M_I                   [  13412070]
[................................fdn.ic..r.......................................]-( 18501453120000) 0x555555554784.0 JMP_I                     [  13412071]
[................................fdn.ic..r.......................................]-( 18501453120000) 0x555555554784.1 JMP_I                     [  13412072]
[................................fdn.pic.r.......................................]-( 18501453120000) 0x555555554784.2 JMP_I                     [  13412073]
[...................................fdn.ic.r.....................................]-( 18501453120000) 0x555555554793.0 CMP_M_I                   [  13412085]
[...................................fdn.ic..r....................................]-( 18501453120000) 0x555555554793.1 CMP_M_I                   [  13412086]
[...................................fdn.p.ic..r..................................]-( 18501453120000) 0x555555554793.2 CMP_M_I                   [  13412087]
[...................................fdn.ic....r..................................]-( 18501453120000) 0x555555554797.0 JLE_I                     [  13412088]
[...................................fdn.ic....r..................................]-( 18501453120000) 0x555555554797.1 JLE_I                     [  13412089]
[...................................fdn.p..ic.r..................................]-( 18501453120000) 0x555555554797.2 JLE_I                     [  13412090]
[...............................................fdn.ic.r.........................]-( 18501453120000) 0x555555554786.0 CALL_NEAR_I               [  13412108]
[...............................................fdn.ic.r.........................]-( 18501453120000) 0x555555554786.1 CALL_NEAR_I               [  13412109]
[...............................................fdn.pic.r........................]-( 18501453120000) 0x555555554786.2 CALL_NEAR_I               [  13412110]
[...............................................fdn.ic..r........................]-( 18501453120000) 0x555555554786.3 CALL_NEAR_I               [  13412111]
[...............................................fdn.pic.r........................]-( 18501453120000) 0x555555554786.4 CALL_NEAR_I               [  13412112]
[................................................................fdn.ic.r........]-( 18501453120000) 0x5555555546fa.0 PUSH_R                    [  13412119]
[................................................................fdn.ic.r........]-( 18501453120000) 0x5555555546fa.1 PUSH_R                    [  13412120]
[................................................................fdn.pic.r.......]-( 18501453120000) 0x5555555546fb.0 MOV_R_R                   [  13412121]
[n.ic.r........................................................................fd]-( 18501453120000) 0x5555555546fe.0 SUB_R_I                   [  13412122]
[n.pic.r.......................................................................fd]-( 18501453120000) 0x5555555546fe.1 SUB_R_I                   [  13412123]
[n.ic..r.......................................................................fd]-( 18501453120000) 0x555555554702.0 MOV_R_M                   [  13412124]
[n.p.ic.r......................................................................fd]-( 18501453120000) 0x55555555470b.0 MOV_M_R                   [  13412125]
[n.p.ic.r......................................................................fd]-( 18501453120000) 0x55555555470f.0 XOR_R_R                   [  13412126]
[n.ic...r......................................................................fd]-( 18501453120000) 0x555555554711.0 MOV_R_I                   [  13412127]
[n.ic...r......................................................................fd]-( 18501453120000) 0x555555554718.0 MOV_R_I                   [  13412128]
[n.ic...r......................................................................fd]-( 18501453120000) 0x55555555471f.0 SYSCALL_64                [  13412129]
[dn.ic..r.......................................................................f]-( 18501453120000) 0x55555555471f.1 SYSCALL_64                [  13412130]
[dn.p.ic....r...................................................................f]-( 18501453120000) 0x55555555471f.2 SYSCALL_64                [  13412131]
[dn.ic......r...................................................................f]-( 18501453120000) 0x55555555471f.3 SYSCALL_64                [  13412132]
[dn.p..ic...r...................................................................f]-( 18501453120000) 0x55555555471f.4 SYSCALL_64                [  13412133]
[dn.ic......r...................................................................f]-( 18501453120000) 0x55555555471f.5 SYSCALL_64                [  13412134]
[dn.pic.....r...................................................................f]-( 18501453120000) 0x55555555471f.6 SYSCALL_64                [  13412135]
[dn.p.ic....r...................................................................f]-( 18501453120000) 0x55555555471f.7 SYSCALL_64                [  13412136]
[dn.p..ic...r...................................................................f]-( 18501453120000) 0x55555555471f.8 SYSCALL_64                [  13412137]
[fdn.ic.....r....................................................................]-( 18501453200000) 0x55555555471f.9 SYSCALL_64                [  13412138]
[fdn.ic......r...................................................................]-( 18501453200000) 0x55555555471f.10 SYSCALL_64                [  13412139]
[fdn.ic......r...................................................................]-( 18501453200000) 0x55555555471f.11 SYSCALL_64                [  13412140]
[fdn.pic.....r...................................................................]-( 18501453200000) 0x55555555471f.12 SYSCALL_64                [  13412141]
[...............fdn...ic.r.......................................................]-( 18501453200000) 0x55555555471f.13 SYSCALL_64                [  13412179]
[...............fdn...pic.r......................................................]-( 18501453200000) 0x55555555471f.14 SYSCALL_64                [  13412180]
[...............fdn...ic..r......................................................]-( 18501453200000) 0x55555555471f.15 SYSCALL_64                [  13412181]
[...............fdn...ic..r......................................................]-( 18501453200000) 0x55555555471f.16 SYSCALL_64                [  13412182]
[...............fdn...ic..r......................................................]-( 18501453200000) 0x55555555471f.17 SYSCALL_64                [  13412183]
[...............fdn...pic.r......................................................]-( 18501453200000) 0x55555555471f.18 SYSCALL_64                [  13412184]
[...............fdn...ic..r......................................................]-( 18501453200000) 0x55555555471f.19 SYSCALL_64                [  13412185]
[...............fdn...pic.r......................................................]-( 18501453200000) 0x55555555471f.20 SYSCALL_64                [  13412186]
[................f...dn.ic.r.....................................................]-( 18501453200000) 0x55555555471f.21 SYSCALL_64                [  13412187]
[................f...dn.pic.r....................................................]-( 18501453200000) 0x55555555471f.22 SYSCALL_64                [  13412188]
[................f...dn.p.ic.r...................................................]-( 18501453200000) 0x55555555471f.23 SYSCALL_64                [  13412189]
[................f...dn.p..ic.r..................................................]-( 18501453200000) 0x55555555471f.24 SYSCALL_64                [  13412190]
[.................f..dn.ic....r..................................................]-( 18501453200000) 0xffffffff81600010.0 SWAPGS                    [  13412191]
[.................f..dn.ic....r..................................................]-( 18501453200000) 0xffffffff81600010.1 SWAPGS                    [  13412192]
[.................f..dn.p........ic.r............................................]-( 18501453200000) 0xffffffff81600010.2 SWAPGS                    [  13412193]
[.................f..dn................p.ic.r....................................]-( 18501453200000) 0xffffffff81600010.3 SWAPGS                    [  13412194]
[.................f...dn.......................ic.r..............................]-( 18501453200000) 0xffffffff81600013.0 MOV_M_R                   [  13412195]
[.................f...dn.......................ic.r..............................]-( 18501453200000) 0xffffffff8160001c.0 JMP_I                     [  13412196]
[.................f...dn.......................ic.r..............................]-( 18501453200000) 0xffffffff8160001c.1 JMP_I                     [  13412197]
[.................f...dn.......................pic.r.............................]-( 18501453200000) 0xffffffff8160001c.2 JMP_I                     [  13412198]
[..................f..........................dn.ic..r...........................]-( 18501453200000) 0xffffffff81600030.0 MOV_R_M                   [  13412199]
[..................f..........................dn.ic..r...........................]-( 18501453200000) 0xffffffff81600039.0 PUSH_I                    [  13412200]
[..................f..........................dn.p.ic.r..........................]-( 18501453200000) 0xffffffff81600039.1 PUSH_I                    [  13412201]
[..................f..........................dn.p.ic.r..........................]-( 18501453200000) 0xffffffff81600039.2 PUSH_I                    [  13412202]
[...................f.........................dn.ic...r..........................]-( 18501453200000) 0xffffffff8160003b.0 PUSH_M                    [  13412203]
[...................f.........................dn.p..ic.r.........................]-( 18501453200000) 0xffffffff8160003b.1 PUSH_M                    [  13412204]
[...................f.........................dn.p..ic.r.........................]-( 18501453200000) 0xffffffff8160003b.2 PUSH_M                    [  13412205]
[...................f.........................dn.p...ic.r........................]-( 18501453200000) 0xffffffff81600043.0 PUSH_R                    [  13412206]
[...................f...........................dn.p.ic.r........................]-( 18501453200000) 0xffffffff81600043.1 PUSH_R                    [  13412207]
[...................f...........................dn.ic...r........................]-( 18501453200000) 0xffffffff81600045.0 PUSH_I                    [  13412208]
[...................f...........................dn.p..ic.r.......................]-( 18501453200000) 0xffffffff81600045.1 PUSH_I                    [  13412209]
[...................f...........................dn.p..ic.r.......................]-( 18501453200000) 0xffffffff81600045.2 PUSH_I                    [  13412210]
[....................f..........................dn.p...ic.r......................]-( 18501453200000) 0xffffffff81600047.0 PUSH_R                    [  13412211]
[....................f..........................dn.p...ic.r......................]-( 18501453200000) 0xffffffff81600047.1 PUSH_R                    [  13412212]
[....................f..........................dn.p....ic.r.....................]-( 18501453200000) 0xffffffff81600048.0 PUSH_R                    [  13412213]
[....................f..........................dn.p....ic.r.....................]-( 18501453200000) 0xffffffff81600048.1 PUSH_R                    [  13412214]
[....................f...........................dn.p....ic.r....................]-( 18501453200000) 0xffffffff81600049.0 PUSH_R                    [  13412215]
[....................f...........................dn.p....ic.r....................]-( 18501453200000) 0xffffffff81600049.1 PUSH_R                    [  13412216]
[....................f...........................dn.p.....ic.r...................]-( 18501453200000) 0xffffffff8160004a.0 PUSH_R                    [  13412217]
[....................f...........................dn.p.....ic.r...................]-( 18501453200000) 0xffffffff8160004a.1 PUSH_R                    [  13412218]
[.....................f..........................dn.p......ic.r..................]-( 18501453200000) 0xffffffff8160004b.0 PUSH_R                    [  13412219]
[.....................f..........................dn.p......ic.r..................]-( 18501453200000) 0xffffffff8160004b.1 PUSH_R                    [  13412220]
[.....................f..........................dn.p.......ic.r.................]-( 18501453200000) 0xffffffff8160004c.0 PUSH_R                    [  13412221]
[.....................f..........................dn.p.......ic.r.................]-( 18501453200000) 0xffffffff8160004c.1 PUSH_R                    [  13412222]
[.....................f...........................dn.ic........r.................]-( 18501453200000) 0xffffffff8160004d.0 PUSH_I                    [  13412223]
[.....................f...........................dn.p.......ic.r................]-( 18501453200000) 0xffffffff8160004d.1 PUSH_I                    [  13412224]

```
Output of printf which we put in dyn_inst.cc to track syscall microops:
```
Count:2200 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : limm   t1, 0xffffffffffffffff Fetch:18501453198000 Decode:18501453199000 Rename:18501453200000 Dispatch: 18501453202000 Issue: 18501453202000 Complete:18501453203000 Commit:18501453207000
Count:2201 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : rdip   ecx, ecx Fetch:18501453199000 Decode:18501453200000 Rename:18501453201000 Dispatch: 18501453203000 Issue: 18501453203000 Complete:18501453204000 Commit:18501453207000
Count:2202 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : rflags   t2d, t2d Fetch:18501453199000 Decode:18501453200000 Rename:18501453201000 Dispatch: 18501453203000 Issue: 18501453205000 Complete:18501453206000 Commit:18501453211000
Count:2203 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : limm   t3, 0xfffffffffffeffff Fetch:18501453199000 Decode:18501453200000 Rename:18501453201000 Dispatch: 18501453203000 Issue: 18501453203000 Complete:18501453204000 Commit:18501453211000
Count:2204 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : and   r11, t2, t3 Fetch:18501453199000 Decode:18501453200000 Rename:18501453201000 Dispatch: 18501453203000 Issue: 18501453206000 Complete:18501453207000 Commit:18501453211000
Count:2205 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : rdval   t3d, %ctrl101 Fetch:18501453199000 Decode:18501453200000 Rename:18501453201000 Dispatch: 18501453203000 Issue: 18501453203000 Complete:18501453204000 Commit:18501453211000
Count:2206 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : srli   t3, t3, 0x20 Fetch:18501453199000 Decode:18501453200000 Rename:18501453201000 Dispatch: 18501453203000 Issue: 18501453204000 Complete:18501453205000 Commit:18501453211000
Count:2207 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : andi   t3b, t3b, 0xfc Fetch:18501453199000 Decode:18501453200000 Rename:18501453201000 Dispatch: 18501453203000 Issue: 18501453205000 Complete:18501453206000 Commit:18501453211000
Count:2208 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : wrsel   CS, t3d Fetch:18501453199000 Decode:18501453200000 Rename:18501453201000 Dispatch: 18501453203000 Issue: 18501453206000 Complete:18501453207000 Commit:18501453211000
Count:2209 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : wrbase   CS, t0 Fetch:18501453200000 Decode:18501453201000 Rename:18501453202000 Dispatch: 18501453204000 Issue: 18501453204000 Complete:18501453205000 Commit:18501453211000
Count:2210 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : wrlimit   CS, t1d Fetch:18501453200000 Decode:18501453201000 Rename:18501453202000 Dispatch: 18501453204000 Issue: 18501453204000 Complete:18501453205000 Commit:18501453212000
Count:2211 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : limm   t4, 0xaad0 Fetch:18501453200000 Decode:18501453201000 Rename:18501453202000 Dispatch: 18501453204000 Issue: 18501453204000 Complete:18501453205000 Commit:18501453212000
Count:2212 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : wrattr   CS, t4d Fetch:18501453200000 Decode:18501453201000 Rename:18501453202000 Dispatch: 18501453204000 Issue: 18501453205000 Complete:18501453206000 Commit:18501453212000
Count:2213 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : addi   t3d, t3d, 0x8 Fetch:18501453215000 Decode:18501453216000 Rename:18501453217000 Dispatch: 18501453221000 Issue: 18501453221000 Complete:18501453222000 Commit:18501453224000
Count:2214 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : wrsel   SS, t3d Fetch:18501453215000 Decode:18501453216000 Rename:18501453217000 Dispatch: 18501453221000 Issue: 18501453222000 Complete:18501453223000 Commit:18501453225000
Count:2215 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : wrbase   SS, t0 Fetch:18501453215000 Decode:18501453216000 Rename:18501453217000 Dispatch: 18501453221000 Issue: 18501453221000 Complete:18501453222000 Commit:18501453225000
Count:2216 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : wrlimit   SS, t1d Fetch:18501453215000 Decode:18501453216000 Rename:18501453217000 Dispatch: 18501453221000 Issue: 18501453221000 Complete:18501453222000 Commit:18501453225000
Count:2217 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : limm   t4, 0xb2c8 Fetch:18501453215000 Decode:18501453216000 Rename:18501453217000 Dispatch: 18501453221000 Issue: 18501453221000 Complete:18501453222000 Commit:18501453225000
Count:2218 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : wrattr   SS, t4d Fetch:18501453215000 Decode:18501453216000 Rename:18501453217000 Dispatch: 18501453221000 Issue: 18501453222000 Complete:18501453223000 Commit:18501453225000
 Count:2219 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : rdval   t7, %ctrl102 Fetch:18501453215000 Decode:18501453216000 Rename:18501453217000 Dispatch: 18501453221000 Issue: 18501453221000 Complete:18501453222000 Commit:18501453225000
Count:2220 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : wrip   t0, t7 Fetch:18501453215000 Decode:18501453216000 Rename:18501453217000 Dispatch: 18501453221000 Issue: 18501453222000 Complete:18501453223000 Commit:18501453225000
Count:2221 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : rdval   t3, %ctrl104 Fetch:18501453216000 Decode:18501453220000 Rename:18501453221000 Dispatch: 18501453223000 Issue: 18501453223000 Complete:18501453224000 Commit:18501453226000
Count:2222 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : xor   t3, t3, t1 Fetch:18501453216000 Decode:18501453220000 Rename:18501453221000 Dispatch: 18501453223000 Issue: 18501453224000 Complete:18501453225000 Commit:18501453227000
Count:2223 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : and   t3, t3, r11 Fetch:18501453216000 Decode:18501453220000 Rename:18501453221000 Dispatch: 18501453223000 Issue: 18501453225000 Complete:18501453226000 Commit:18501453228000 
Count:2224 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : wrflags   t3d, t0d Fetch:18501453216000 Decode:18501453220000 Rename:18501453221000 Dispatch: 18501453223000 Issue: 18501453226000 Complete:18501453227000 Commit:18501453229000

```

Key Observation to note:
1. Total Time taken by syscall instruction to execute is 22 cycles.
2. Now we are only loosing some cycles when we are squasing the ROB when we encounter the wrattr microop.


### Case4:  Flag IsNonSpeculative, IsSerializeAfter and IsSquashAfter are false for all microops except wrattr microop for which all 3 flag is true for our syscall

We changed 5 functions in dyn_inst.hh as follows:
```c++
bool isSerializing()  const { 
        const std::string s = staticInst->disassemble(pcState().instAddr()); 
        if(pcState().instAddr()== 0x55555555471f && s.find("SYSCALL_64 : wrattr") == std::string::npos){
            std::cout<<"Comes here is serializing: "<< staticInst->disassemble(pcState().instAddr()) <<std::endl;
            return false;
        }
        return staticInst->isSerializing(); 
    }
    bool isSerializeBefore() const
    {
        const std::string s = staticInst->disassemble(pcState().instAddr());    
        if(pcState().instAddr()== 0x55555555471f && s.find("SYSCALL_64 : wrattr") == std::string::npos && s.find("SYSCALL_64 : addi") == std::string::npos){
            std::cout<<"Comes here isserialing before: "<< staticInst->disassemble(pcState().instAddr()) <<std::endl;
            return false;
        }
        return staticInst->isSerializeBefore() || status[SerializeBefore];
    }
    bool
    isSerializeAfter() const
    {
        const std::string s = staticInst->disassemble(pcState().instAddr());    
        if(pcState().instAddr()== 0x55555555471f&& s.find("SYSCALL_64 : wrattr") == std::string::npos){
            std::cout<<"Comes here isserialing after: "<< staticInst->disassemble(pcState().instAddr()) <<std::endl;
            return false;
        }
        return staticInst->isSerializeAfter() || status[SerializeAfter];
    }
    bool isSquashAfter() const { 
        
        const std::string s = staticInst->disassemble(pcState().instAddr());    
        if(pcState().instAddr()== 0x55555555471f && s.find("SYSCALL_64 : wrattr") == std::string::npos){
            std::cout<<"Comes here squash after: "<< staticInst->disassemble(pcState().instAddr()) <<std::endl;
            return false;
        }

        return staticInst->isSquashAfter(); }
    
    bool isNonSpeculative() const { 
        const std::string s = staticInst->disassemble(pcState().instAddr());    
        if(pcState().instAddr()== 0x55555555471f&& s.find("SYSCALL_64 : wrattr") == std::string::npos){
            std::cout<<"Comes here nonspec: "<< staticInst->disassemble(pcState().instAddr()) <<std::endl;
            return false;
        }
        return staticInst->isNonSpeculative(); }
```

O3PipeView Utility Output:
```
[.................................................fdn.p..ic.....r................]-( 18849403920000) 0x7ffff7a62bc0.2 JNZ_I                     [  13219782]
[.................................................fdn.ic........r................]-( 18849403920000) 0x7ffff7a62bc2.0 MOV_M_I                   [  13219783]
[.................................................fdn.pic.......r................]-( 18849403920000) 0x7ffff7a62bc2.1 MOV_M_I                   [  13219784]
[.................................................fdn.ic........r................]-( 18849403920000) 0x7ffff7a62bca.0 CMP_P_I                   [  13219785]
[.................................................fdn.ic........r................]-( 18849403920000) 0x7ffff7a62bca.1 CMP_P_I                   [  13219786]
[.................................................fdn.pic........r...............]-( 18849403920000) 0x7ffff7a62bca.2 CMP_P_I                   [  13219787]
[..................................................fdn.p.ic......r...............]-( 18849403920000) 0x7ffff7a62bca.3 CMP_P_I                   [  13219788]
[..................................................fdn.ic........r...............]-( 18849403920000) 0x7ffff7a62bd1.0 JZ_I                      [  13219789]
[..................................................fdn.ic........r...............]-( 18849403920000) 0x7ffff7a62bd1.1 JZ_I                      [  13219790]
[..................................................fdn.p..ic.....r...............]-( 18849403920000) 0x7ffff7a62bd1.2 JZ_I                      [  13219791]
[..............................................................f...dn.ic..r......]-( 18849403920000) 0x7ffff7a62bda.0 DEC_M                     [  13219831]
[..............................................................f...dn.p.ic..r....]-( 18849403920000) 0x7ffff7a62bda.1 DEC_M                     [  13219832]
[..............................................................f...dn.p..ic.r....]-( 18849403920000) 0x7ffff7a62bda.2 DEC_M                     [  13219833]
[..............................................................f...dn.ic....r....]-( 18849403920000) 0x7ffff7a62bdc.0 JZ_I                      [  13219834]
[..............................................................f...dn.ic....r....]-( 18849403920000) 0x7ffff7a62bdc.1 JZ_I                      [  13219835]
[..............................................................f...dn.p..ic.r....]-( 18849403920000) 0x7ffff7a62bdc.2 JZ_I                      [  13219836]
[ic.r........................................................................fdn.]-( 18849403920000) 0x7ffff7a62bf4.0 ADD_R_I                   [  13219874]
[pic..r......................................................................fdn.]-( 18849403920000) 0x7ffff7a62bf4.1 ADD_R_I                   [  13219875]
[ic...r......................................................................fdn.]-( 18849403920000) 0x7ffff7a62bf8.0 MOV_R_R                   [  13219876]
[p.ic...............r........................................................fdn.]-( 18849403920000) 0x7ffff7a62bfa.0 POP_R                     [  13219877]
[p.ic...............r........................................................fdn.]-( 18849403920000) 0x7ffff7a62bfa.1 POP_R                     [  13219878]
[p................ic..r......................................................fdn.]-( 18849403920000) 0x7ffff7a62bfa.2 POP_R                     [  13219879]
[p..ic................r......................................................fdn.]-( 18849403920000) 0x7ffff7a62bfb.0 POP_R                     [  13219880]
[p..ic................r......................................................fdn.]-( 18849403920000) 0x7ffff7a62bfb.1 POP_R                     [  13219881]
[.p.................ic..r.....................................................fdn]-( 18849403920000) 0x7ffff7a62bfb.2 POP_R                     [  13219882]
[.p..ic.................r.....................................................fdn]-( 18849403920000) 0x7ffff7a62bfc.0 POP_R                     [  13219883]
[.p..ic.................r.....................................................fdn]-( 18849403920000) 0x7ffff7a62bfc.1 POP_R                     [  13219884]
[.p..................ic.r.....................................................fdn]-( 18849403920000) 0x7ffff7a62bfc.2 POP_R                     [  13219885]
[.p...ic................r.....................................................fdn]-( 18849403920000) 0x7ffff7a62bfe.0 POP_R                     [  13219886]
[.p...ic................r.....................................................fdn]-( 18849403920000) 0x7ffff7a62bfe.1 POP_R                     [  13219887]
[.p..................ic.r.....................................................fdn]-( 18849403920000) 0x7ffff7a62bfe.2 POP_R                     [  13219888]
[n.p...ic...............r......................................................fd]-( 18849403920000) 0x7ffff7a62c00.0 RET_NEAR                  [  13219889]
[n.p...ic................r.....................................................fd]-( 18849403920000) 0x7ffff7a62c00.1 RET_NEAR                  [  13219890]
[n.p.................ic..r.....................................................fd]-( 18849403920000) 0x7ffff7a62c00.2 RET_NEAR                  [  13219891]
[....................................................fdn.ic.r....................]-( 18849404000000) 0x55555555477d.0 MOV_M_I                   [  13219896]
[....................................................fdn.pic.r...................]-( 18849404000000) 0x55555555477d.1 MOV_M_I                   [  13219897]
[....................................................fdn.ic..r...................]-( 18849404000000) 0x555555554784.0 JMP_I                     [  13219898]
[....................................................fdn.ic..r...................]-( 18849404000000) 0x555555554784.1 JMP_I                     [  13219899]
[....................................................fdn.pic.r...................]-( 18849404000000) 0x555555554784.2 JMP_I                     [  13219900]
[.......................................................fdn.ic.r.................]-( 18849404000000) 0x555555554793.0 CMP_M_I                   [  13219912]
[.......................................................fdn.ic..r................]-( 18849404000000) 0x555555554793.1 CMP_M_I                   [  13219913]
[.......................................................fdn.p.ic..r..............]-( 18849404000000) 0x555555554793.2 CMP_M_I                   [  13219914]
[.......................................................fdn.ic....r..............]-( 18849404000000) 0x555555554797.0 JLE_I                     [  13219915]
[.......................................................fdn.ic....r..............]-( 18849404000000) 0x555555554797.1 JLE_I                     [  13219916]
[.......................................................fdn.p..ic.r..............]-( 18849404000000) 0x555555554797.2 JLE_I                     [  13219917]
[...................................................................fdn.ic.r.....]-( 18849404000000) 0x555555554786.0 CALL_NEAR_I               [  13219935]
[...................................................................fdn.ic.r.....]-( 18849404000000) 0x555555554786.1 CALL_NEAR_I               [  13219936]
[...................................................................fdn.pic.r....]-( 18849404000000) 0x555555554786.2 CALL_NEAR_I               [  13219937]
[...................................................................fdn.ic..r....]-( 18849404000000) 0x555555554786.3 CALL_NEAR_I               [  13219938]
[...................................................................fdn.pic.r....]-( 18849404000000) 0x555555554786.4 CALL_NEAR_I               [  13219939]
[....fdn.ic.r....................................................................]-( 18849404080000) 0x5555555546fa.0 PUSH_R                    [  13219946]
[....fdn.ic.r....................................................................]-( 18849404080000) 0x5555555546fa.1 PUSH_R                    [  13219947]
[....fdn.pic.r...................................................................]-( 18849404080000) 0x5555555546fb.0 MOV_R_R                   [  13219948]
[..................fdn.ic.r......................................................]-( 18849404080000) 0x5555555546fe.0 SUB_R_I                   [  13219949]
[..................fdn.pic.r.....................................................]-( 18849404080000) 0x5555555546fe.1 SUB_R_I                   [  13219950]
[..................fdn.ic..r.....................................................]-( 18849404080000) 0x555555554702.0 MOV_R_M                   [  13219951]
[..................fdn.p.ic.r....................................................]-( 18849404080000) 0x55555555470b.0 MOV_M_R                   [  13219952]
[..................fdn.p.ic.r....................................................]-( 18849404080000) 0x55555555470f.0 XOR_R_R                   [  13219953]
[..................fdn.ic...r....................................................]-( 18849404080000) 0x555555554711.0 MOV_R_I                   [  13219954]
[..................fdn.ic...r....................................................]-( 18849404080000) 0x555555554718.0 MOV_R_I                   [  13219955]
[..................fdn.ic...r....................................................]-( 18849404080000) 0x55555555471f.0 SYSCALL_64                [  13219956]
[...................fdn.ic..r....................................................]-( 18849404080000) 0x55555555471f.1 SYSCALL_64                [  13219957]
[...................fdn.p.ic....r................................................]-( 18849404080000) 0x55555555471f.2 SYSCALL_64                [  13219958]
[...................fdn.ic......r................................................]-( 18849404080000) 0x55555555471f.3 SYSCALL_64                [  13219959]
[...................fdn.p..ic...r................................................]-( 18849404080000) 0x55555555471f.4 SYSCALL_64                [  13219960]
[...................fdn.ic......r................................................]-( 18849404080000) 0x55555555471f.5 SYSCALL_64                [  13219961]
[...................fdn.pic.....r................................................]-( 18849404080000) 0x55555555471f.6 SYSCALL_64                [  13219962]
[...................fdn.p.ic....r................................................]-( 18849404080000) 0x55555555471f.7 SYSCALL_64                [  13219963]
[...................fdn.p..ic...r................................................]-( 18849404080000) 0x55555555471f.8 SYSCALL_64                [  13219964]
[....................fdn.ic.....r................................................]-( 18849404080000) 0x55555555471f.9 SYSCALL_64                [  13219965]
[....................fdn.ic......r...............................................]-( 18849404080000) 0x55555555471f.10 SYSCALL_64                [  13219966]
[....................fdn.ic......r...............................................]-( 18849404080000) 0x55555555471f.11 SYSCALL_64                [  13219967]
[....................fdn.p..........ic.r.........................................]-( 18849404080000) 0x55555555471f.12 SYSCALL_64                [  13219968]
[.........................................fdn...ic.r.............................]-( 18849404080000) 0x55555555471f.13 SYSCALL_64                [  13220006]
[.........................................fdn...pic.r............................]-( 18849404080000) 0x55555555471f.14 SYSCALL_64                [  13220007]
[.........................................fdn...ic..r............................]-( 18849404080000) 0x55555555471f.15 SYSCALL_64                [  13220008]
[.........................................fdn...ic..r............................]-( 18849404080000) 0x55555555471f.16 SYSCALL_64                [  13220009]
[.........................................fdn...ic..r............................]-( 18849404080000) 0x55555555471f.17 SYSCALL_64                [  13220010]
[.........................................fdn...p......ic.r......................]-( 18849404080000) 0x55555555471f.18 SYSCALL_64                [  13220011]
[.........................................fdn...ic........r......................]-( 18849404080000) 0x55555555471f.19 SYSCALL_64                [  13220012]
[.........................................fdn...pic.......r......................]-( 18849404080000) 0x55555555471f.20 SYSCALL_64                [  13220013]
[..........................................f...dn.ic......r......................]-( 18849404080000) 0x55555555471f.21 SYSCALL_64                [  13220014]
[..........................................f...dn.pic.....r......................]-( 18849404080000) 0x55555555471f.22 SYSCALL_64                [  13220015]
[..........................................f...dn.p.ic....r......................]-( 18849404080000) 0x55555555471f.23 SYSCALL_64                [  13220016]
[..........................................f...dn.p..ic...r......................]-( 18849404080000) 0x55555555471f.24 SYSCALL_64                [  13220017]
[............................................f...dn.ic....r......................]-( 18849404080000) 0xffffffff81600010.0 SWAPGS                    [  13220018]
[............................................f...dn.ic.....r.....................]-( 18849404080000) 0xffffffff81600010.1 SWAPGS                    [  13220019]
[............................................f...dn.p.........ic.r...............]-( 18849404080000) 0xffffffff81600010.2 SWAPGS                    [  13220020]
[............................................f...dn.................p.ic.r.......]-( 18849404080000) 0xffffffff81600010.3 SWAPGS                    [  13220021]
[............................................f...dn.........................ic.r.]-( 18849404080000) 0xffffffff81600013.0 MOV_M_R                   [  13220022]
[............................................f...dn.........................ic.r.]-( 18849404080000) 0xffffffff8160001c.0 JMP_I                     [  13220023]
[............................................f...dn.........................ic.r.]-( 18849404080000) 0xffffffff8160001c.1 JMP_I                     [  13220024]
[............................................f...dn.........................pic.r]-( 18849404080000) 0xffffffff8160001c.2 JMP_I                     [  13220025]
[.............................................f...dn........................ic..r]-( 18849404080000) 0xffffffff81600030.0 MOV_R_M                   [  13220026]
[.............................................f...dn........................ic..r]-( 18849404080000) 0xffffffff81600039.0 PUSH_I                    [  13220027]
[r............................................f...dn........................p.ic.]-( 18849404080000) 0xffffffff81600039.1 PUSH_I                    [  13220028]
[r............................................f...dn........................p.ic.]-( 18849404080000) 0xffffffff81600039.2 PUSH_I                    [  13220029]
[r.............................................f..dn.........................ic..]-( 18849404080000) 0xffffffff8160003b.0 PUSH_M                    [  13220030]
[.r............................................f..dn.........................p.ic]-( 18849404080000) 0xffffffff8160003b.1 PUSH_M                    [  13220031]
[.r............................................f..dn.........................p.ic]-( 18849404080000) 0xffffffff8160003b.2 PUSH_M                    [  13220032]
[c.r...........................................f..dn.........................p..i]-( 18849404080000) 0xffffffff81600043.0 PUSH_R                    [  13220033]
[c.r...........................................f............................dn.pi]-( 18849404080000) 0xffffffff81600043.1 PUSH_R                    [  13220034]
[..r...........................................f............................dn.ic]-( 18849404080000) 0xffffffff81600045.0 PUSH_I                    [  13220035]
[ic.r..........................................f............................dn.p.]-( 18849404080000) 0xffffffff81600045.1 PUSH_I                    [  13220036]
[ic.r..........................................f............................dn.p.]-( 18849404080000) 0xffffffff81600045.2 PUSH_I                    [  13220037]
[.ic.r..........................................f...........................dn.p.]-( 18849404080000) 0xffffffff81600047.0 PUSH_R                    [  13220038]
[.ic.r..........................................f...........................dn.p.]-( 18849404080000) 0xffffffff81600047.1 PUSH_R                    [  13220039]
[..ic.r.........................................f...........................dn.p.]-( 18849404080000) 0xffffffff81600048.0 PUSH_R                    [  13220040]
[..ic.r.........................................f...........................dn.p.]-( 18849404080000) 0xffffffff81600048.1 PUSH_R                    [  13220041]
[...ic.r........................................f............................dn.p]-( 18849404080000) 0xffffffff81600049.0 PUSH_R                    [  13220042]
[...ic.r........................................f............................dn.p]-( 18849404080000) 0xffffffff81600049.1 PUSH_R                    [  13220043]
[....ic.r.......................................f............................dn.p]-( 18849404080000) 0xffffffff8160004a.0 PUSH_R                    [  13220044]
[....ic.r.......................................f............................dn.p]-( 18849404080000) 0xffffffff8160004a.1 PUSH_R                    [  13220045]
[.....ic.r.......................................f...........................dn.p]-( 18849404080000) 0xffffffff8160004b.0 PUSH_R                    [  13220046]
[.....ic.r.......................................f...........................dn.p]-( 18849404080000) 0xffffffff8160004b.1 PUSH_R                    [  13220047]
[......ic.r......................................f...........................dn.p]-( 18849404080000) 0xffffffff8160004c.0 PUSH_R                    [  13220048]
[......ic.r......................................f...........................dn.p]-( 18849404080000) 0xffffffff8160004c.1 PUSH_R                    [  13220049]
[.ic......r......................................f.............................dn]-( 18849404080000) 0xffffffff8160004d.0 PUSH_I                    [  13220050]
[.p.....ic.r.....................................f.............................dn]-( 18849404080000) 0xffffffff8160004d.1 PUSH_I                    [  13220051]
[.p.....ic.r.....................................f.............................dn]-( 18849404080000) 0xffffffff8160004d.2 PUSH_I                    [  13220052]
[.p......ic.r....................................f.............................dn]-( 18849404080000) 0xffffffff8160004f.0 PUSH_R                    [  13220053]
[.p......ic.r.....................................f............................dn]-( 18849404080000) 0xffffffff8160004f.1 PUSH_R                    [  13220054]
[.p.......ic.r....................................f............................dn]-( 18849404080000) 0xffffffff81600051.0 PUSH_R                    [  13220055]
[.p.......ic.r....................................f............................dn]-( 18849404080000) 0xffffffff81600051.1 PUSH_R                    [  13220056]
[.p........ic.r...................................f............................dn]-( 18849404080000) 0xffffffff81600053.0 PUSH_R                    [  13220057]
[n.p.......ic.r...................................f.............................d]-( 18849404080000) 0xffffffff81600053.1 PUSH_R                    [  13220058]
[n.p........ic.r..................................f.............................d]-( 18849404080000) 0xffffffff81600055.0 PUSH_R                    [  13220059]
[n.p........ic.r..................................f.............................d]-( 18849404080000) 0xffffffff81600055.1 PUSH_R                    [  13220060]
[n.p.........ic.r.................................f.............................d]-( 18849404080000) 0xffffffff81600057.0 PUSH_R                    [  13220061]
[n.p.........ic.r..................................f............................d]-( 18849404080000) 0xffffffff81600057.1 PUSH_R                    [  13220062]
[n.p..........ic.r.................................f............................d]-( 18849404080000) 0xffffffff81600058.0 PUSH_R                    [  13220063]
[n.p..........ic.r.................................f............................d]-( 18849404080000) 0xffffffff81600058.1 PUSH_R                    [  13220064]
[n.p...........ic.r................................f............................d]-( 18849404080000) 0xffffffff81600059.0 PUSH_R                    [  13220065]
[dn.p..........ic.r................................f.............................]-( 18849404080000) 0xffffffff81600059.1 PUSH_R                    [  13220066]
[dn.p...........ic.r...............................f.............................]-( 18849404080000) 0xffffffff8160005b.0 PUSH_R                    [  13220067]
[dn.p...........ic.r...............................f.............................]-( 18849404080000) 0xffffffff8160005b.1 PUSH_R                    [  13220068]
[dn.p............ic.r..............................f.............................]-( 18849404080000) 0xffffffff8160005d.0 PUSH_R                    [  13220069]
[dn.p............ic.r...............................f............................]-( 18849404080000) 0xffffffff8160005d.1 PUSH_R                    [  13220070]
[dn.p.............ic.r..............................f............................]-( 18849404080000) 0xffffffff8160005f.0 PUSH_R                    [  13220071]
[dn.p.............ic.r..............................f............................]-( 18849404080000) 0xffffffff8160005f.1 PUSH_R                    [  13220072]
[dn.ic...............r..............................f............................]-( 18849404080000) 0xffffffff81600061.0 XOR_R_R                   [  13220073]
[.dn.ic..............r..............................f............................]-( 18849404080000) 0xffffffff81600063.0 XOR_R_R                   [  13220074]
[.dn.pic.............r..............................f............................]-( 18849404080000) 0xffffffff81600065.0 XOR_R_R                   [  13220075]
[.dn.p.ic............r..............................f............................]-( 18849404080000) 0xffffffff81600068.0 XOR_R_R                   [  13220076]
[.dn.p..ic...........r..............................f............................]-( 18849404080000) 0xffffffff8160006b.0 XOR_R_R                   [  13220077]
[.dn.p...ic..........r...............................f...........................]-( 18849404080000) 0xffffffff8160006e.0 XOR_R_R                   [  13220078]
[.dn.p....ic..........r..............................f...........................]-( 18849404080000) 0xffffffff81600071.0 XOR_R_R                   [  13220079]
[.dn.p.....ic.........r..............................f...........................]-( 18849404080000) 0xffffffff81600073.0 XOR_R_R                   [  13220080]
[.dn.p......ic........r..............................f...........................]-( 18849404080000) 0xffffffff81600075.0 XOR_R_R                   [  13220081]
[..dn.p......ic.......r........................................................f.]-( 18849404080000) 0xffffffff81600078.0 XOR_R_R                   [  13220082]
[..dn.p.......ic......r........................................................f.]-( 18849404080000) 0xffffffff8160007b.0 XOR_R_R                   [  13220083]
[..dn.p........ic.....r.........................................................f]-( 18849404080000) 0xffffffff8160007e.0 XOR_R_R                   [  13220084]
[..dn.ic..............r.........................................................f]-( 18849404080000) 0xffffffff81600081.0 MOV_R_R                   [  13220085]
[..dn.p............ic.r.........................................................f]-( 18849404080000) 0xffffffff81600084.0 MOV_R_R                   [  13220086]
[..dn.ic...............r........................................................f]-( 18849404080000) 0xffffffff81600087.0 CALL_NEAR_I               [  13220087]
[..dn.ic...............r........................................................f]-( 18849404080000) 0xffffffff81600087.1 CALL_NEAR_I               [  13220088]
[..dn.p............ic..r........................................................f]-( 18849404080000) 0xffffffff81600087.2 CALL_NEAR_I               [  13220089]
[...dn.p...........ic..r........................................................f]-( 18849404080000) 0xffffffff81600087.3 CALL_NEAR_I               [  13220090]
[...dn.ic..............r........................................................f]-( 18849404080000) 0xffffffff81600087.4 CALL_NEAR_I               [  13220091]
[f..dn.p............ic.r.........................................................]-( 18849404160000) 0xffffffff81001e8d.0 PUSH_R                    [  13220092]
[f..dn.p............ic.r.........................................................]-( 18849404160000) 0xffffffff81001e8d.1 PUSH_R                    [  13220093]
[f..dn.p............ic.r.........................................................]-( 18849404160000) 0xffffffff81001e8e.0 MOV_R_R                   [  13220094]
[f..dn.p........ic......r........................................................]-( 18849404160000) 0xffffffff81001e91.0 STI                       [  13220095]
[f..dn.p.........ic.....r........................................................]-( 18849404160000) 0xffffffff81001e91.1 STI                       [  13220096]
[f..dn.p.........ic.....r........................................................]-( 18849404160000) 0xffffffff81001e91.2 STI                       [  13220097]
[f...dn.ic..............r........................................................]-( 18849404160000) 0xffffffff81001e91.3 STI                       [  13220098]
[f...dn.pic.............r........................................................]-( 18849404160000) 0xffffffff81001e91.4 STI                       [  13220099]
[.f..dn.p.ic............r........................................................]-( 18849404160000) 0xffffffff81001e91.5 STI                       [  13220100]
[.f..dn.p.........ic....r........................................................]-( 18849404160000) 0xffffffff81001e91.6 STI                       [  13220101]
[.f..dn.p..........ic...r........................................................]-( 18849404160000) 0xffffffff81001e91.7 STI                       [  13220102]
[.f..dn.ic...............r.......................................................]-( 18849404160000) 0xffffffff81001e91.18 STI                       [  13220103]
[.f..dn.p........ic......r.......................................................]-( 18849404160000) 0xffffffff81001e91.19 STI                       [  13220104]
[.f..dn.p....................ic.r................................................]-( 18849404160000) 0xffffffff81001e91.20 STI                       [  13220105]
[..f..dn...........................ic..r.........................................]-( 18849404160000) 0xffffffff81001e92.0 MOV_R_M                   [  13220106]
[..f..dn...........................p.ic..r.......................................]-( 18849404160000) 0xffffffff81001e9b.0 MOV_R_M                   [  13220107]
[..f..dn...........................ic....r.......................................]-( 18849404160000) 0xffffffff81001e9e.0 TEST_R_I                  [  13220108]
[..f..dn...........................p...ic.r......................................]-( 18849404160000) 0xffffffff81001e9e.1 TEST_R_I                  [  13220109]
[..f..dn...........................ic.....r......................................]-( 18849404160000) 0xffffffff81001ea3.0 JZ_I                      [  13220110]
[..f..dn...........................ic.....r......................................]-( 18849404160000) 0xffffffff81001ea3.1 JZ_I                      [  13220111]
[..f..dn...........................p....ic.r.....................................]-( 18849404160000) 0xffffffff81001ea3.2 JZ_I                      [  13220112]
[...f.dn...........................ic......r.....................................]-( 18849404160000) 0xffffffff81001eb0.0 CMP_R_I                   [  13220113]
[...f..dn...........................ic.....r.....................................]-( 18849404160000) 0xffffffff81001eb0.1 CMP_R_I                   [  13220114]
[...f..dn...........................ic.....r.....................................]-( 18849404160000) 0xffffffff81001eb7.0 JNBE_I                    [  13220115]
[...f..dn...........................ic.....r.....................................]-( 18849404160000) 0xffffffff81001eb7.1 JNBE_I                    [  13220116]
[...f..dn...........................pic....r.....................................]-( 18849404160000) 0xffffffff81001eb7.2 JNBE_I                    [  13220117]
[...f..dn...........................ic.....r.....................................]-( 18849404160000) 0xffffffff81001eb9.0 CMP_R_I                   [  13220118]
[...f..dn...........................pic....r.....................................]-( 18849404160000) 0xffffffff81001eb9.1 CMP_R_I                   [  13220119]
[....f.dn...........................p..ic...r....................................]-( 18849404160000) 0xffffffff81001ec0.0 SBB_R_R                   [  13220120]
[....f.dn...........................p...ic..r....................................]-( 18849404160000) 0xffffffff81001ec3.0 AND_R_R                   [  13220121]
[....f.............................dn.p..ic......................................]-( 18849404160000) 0xffffffff81001ec6.0 MOV_R_M                   [  13220122]
[.......................................................r........................]-( 18849404240000)     ...     
[....f.............................dn.p..ic......................................]-( 18849404160000) 0xffffffff81001ece.0 MOV_R_R                   [  13220123]
[.......................................................r........................]-( 18849404240000)     ...     
[....f.............................dn.ic.........................................]-( 18849404160000) 0xffffffff81001ed1.0 CALL_NEAR_I               [  13220124]
[.......................................................r........................]-( 18849404240000)     ...     
[....f.............................dn.ic.........................................]-( 18849404160000) 0xffffffff81001ed1.1 CALL_NEAR_I               [  13220125]
[.......................................................r........................]-( 18849404240000)     ...     
[....f.............................dn.pic........................................]-( 18849404160000) 0xffffffff81001ed1.2 CALL_NEAR_I               [  13220126]
[.......................................................r........................]-( 18849404240000)     ...     
[....f.............................dn.ic.........................................]-( 18849404160000) 0xffffffff81001ed1.3 CALL_NEAR_I               [  13220127]
[.......................................................r........................]-( 18849404240000)     ...     
[.....f............................dn.pic........................................]-( 18849404160000) 0xffffffff81001ed1.4 CALL_NEAR_I               [  13220128]
[.......................................................r........................]-( 18849404240000)     ...     
[......f...........................dn.p..........................................]-( 18849404160000) 0xffffffff81800b60.0 LFENCE                    [  13220129]
[............................................................ic.r................]-( 18849404240000)     ...     
[......f............................dn...........................................]-( 18849404160000) 0xffffffff81800b63.0 JMP_R                     [  13220130]
[..................................................................ic.r..........]-( 18849404240000)     ...     
[....................................................................fdn.ic.r....]-( 18849404320000) 0xffffffff810597d5.0 XOR_R_R                   [  13220186]
[....................................................................fdn.ic.r....]-( 18849404320000) 0xffffffff810597d7.0 MOV_R_I                   [  13220187]

```


Output of printf which we put in dyn_inst.cc to track syscall microops:
```
Count:2200 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : limm   t1, 0xffffffffffffffff Fetch:18849404098000 Decode:18849404099000 Rename:18849404100000 Dispatch: 18849404102000 Issue: 18849404102000 Complete:18849404103000 Commit:18849404107000
Count:2201 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : rdip   ecx, ecx Fetch:18849404099000 Decode:18849404100000 Rename:18849404101000 Dispatch: 18849404103000 Issue: 18849404103000 Complete:18849404104000 Commit:18849404107000
Count:2202 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : rflags   t2d, t2d Fetch:18849404099000 Decode:18849404100000 Rename:18849404101000 Dispatch: 18849404103000 Issue: 18849404105000 Complete:18849404106000 Commit:18849404111000
Count:2203 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : limm   t3, 0xfffffffffffeffff Fetch:18849404099000 Decode:18849404100000 Rename:18849404101000 Dispatch: 18849404103000 Issue: 18849404103000 Complete:18849404104000 Commit:18849404111000
Count:2204 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : and   r11, t2, t3 Fetch:18849404099000 Decode:18849404100000 Rename:18849404101000 Dispatch: 18849404103000 Issue: 18849404106000 Complete:18849404107000 Commit:18849404111000
Count:2205 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : rdval   t3d, %ctrl101 Fetch:18849404099000 Decode:18849404100000 Rename:18849404101000 Dispatch: 18849404103000 Issue: 18849404103000 Complete:18849404104000 Commit:18849404111000
Count:2206 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : srli   t3, t3, 0x20 Fetch:18849404099000 Decode:18849404100000 Rename:18849404101000 Dispatch: 18849404103000 Issue: 18849404104000 Complete:18849404105000 Commit:18849404111000
Count:2207 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : andi   t3b, t3b, 0xfc Fetch:18849404099000 Decode:18849404100000 Rename:18849404101000 Dispatch: 18849404103000 Issue: 18849404105000 Complete:18849404106000 Commit:18849404111000
Count:2208 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : wrsel   CS, t3d Fetch:18849404099000 Decode:18849404100000 Rename:18849404101000 Dispatch: 18849404103000 Issue: 18849404106000 Complete:18849404107000 Commit:18849404111000
Count:2209 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : wrbase   CS, t0 Fetch:18849404100000 Decode:18849404101000 Rename:18849404102000 Dispatch: 18849404104000 Issue: 18849404104000 Complete:18849404105000 Commit:18849404111000
Count:2210 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : wrlimit   CS, t1d Fetch:18849404100000 Decode:18849404101000 Rename:18849404102000 Dispatch: 18849404104000 Issue: 18849404104000 Complete:18849404105000 Commit:18849404112000
Count:2211 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : limm   t4, 0xaad0 Fetch:18849404100000 Decode:18849404101000 Rename:18849404102000 Dispatch: 18849404104000 Issue: 18849404104000 Complete:18849404105000 Commit:18849404112000
Count:2212 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : wrattr   CS, t4d Fetch:18849404100000 Decode:18849404101000 Rename:18849404102000 Dispatch: 18849404104000 Issue: 18849404115000 Complete:18849404116000 Commit:18849404118000
Count:2213 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : addi   t3d, t3d, 0x8 Fetch:18849404121000 Decode:18849404122000 Rename:18849404123000 Dispatch: 18849404127000 Issue: 18849404127000 Complete:18849404128000 Commit:18849404130000
Count:2214 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : wrsel   SS, t3d Fetch:18849404121000 Decode:18849404122000 Rename:18849404123000 Dispatch: 18849404127000 Issue: 18849404128000 Complete:18849404129000 Commit:18849404131000
Count:2215 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : wrbase   SS, t0 Fetch:18849404121000 Decode:18849404122000 Rename:18849404123000 Dispatch: 18849404127000 Issue: 18849404127000 Complete:18849404128000 Commit:18849404131000
Count:2216 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : wrlimit   SS, t1d Fetch:18849404121000 Decode:18849404122000 Rename:18849404123000 Dispatch: 18849404127000 Issue: 18849404127000 Complete:18849404128000 Commit:18849404131000
Count:2217 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : limm   t4, 0xb2c8 Fetch:18849404121000 Decode:18849404122000 Rename:18849404123000 Dispatch: 18849404127000 Issue: 18849404127000 Complete:18849404128000 Commit:18849404131000
Count:2218 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : wrattr   SS, t4d Fetch:18849404121000 Decode:18849404122000 Rename:18849404123000 Dispatch: 18849404127000 Issue: 18849404134000 Complete:18849404135000 Commit:18849404137000
 Count:2219 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : rdval   t7, %ctrl102 Fetch:18849404121000 Decode:18849404122000 Rename:18849404123000 Dispatch: 18849404127000 Issue: 18849404127000 Complete:18849404128000 Commit:18849404137000
Count:2220 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : wrip   t0, t7 Fetch:18849404121000 Decode:18849404122000 Rename:18849404123000 Dispatch: 18849404127000 Issue: 18849404128000 Complete:18849404129000 Commit:18849404137000
Count:2221 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : rdval   t3, %ctrl104 Fetch:18849404122000 Decode:18849404126000 Rename:18849404127000 Dispatch: 18849404129000 Issue: 18849404129000 Complete:18849404130000 Commit:18849404137000
Count:2222 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : xor   t3, t3, t1 Fetch:18849404122000 Decode:18849404126000 Rename:18849404127000 Dispatch: 18849404129000 Issue: 18849404130000 Complete:18849404131000 Commit:18849404137000
Count:2223 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : and   t3, t3, r11 Fetch:18849404122000 Decode:18849404126000 Rename:18849404127000 Dispatch: 18849404129000 Issue: 18849404131000 Complete:18849404132000 Commit:18849404137000
Count:2224 Syscall @address 0x55555555471f Micropc:   SYSCALL_64 : wrflags   t3d, t0d Fetch:18849404122000 Decode:18849404126000 Rename:18849404127000 Dispatch: 18849404129000 Issue: 18849404132000 Complete:18849404133000 Commit:18849404137000

```

Key Points to note:
1. Total Time taken by syscall instruction to execute is 30 cycles.
2. Now we are only loosing some extra cycles when we are adding more flags (Non Speculative and IsSerializing) than the previos case but it help in maintaining correctness in edge cases. We will argue about these cases in next section of Documentation.



### Case 5: Unnecessary MicroOps are removed from the syscall instruction and all the flags of all MicroOps are preserved


O3PipeView Util Output:
```
[.................................................fdn.p..ic.....r................]-( 18849403920000) 0x7ffff7a62bc0.2 JNZ_I                     [  13219782]
[.................................................fdn.ic........r................]-( 18849403920000) 0x7ffff7a62bc2.0 MOV_M_I                   [  13219783]
[.................................................fdn.pic.......r................]-( 18849403920000) 0x7ffff7a62bc2.1 MOV_M_I                   [  13219784]
[.................................................fdn.ic........r................]-( 18849403920000) 0x7ffff7a62bca.0 CMP_P_I                   [  13219785]
[.................................................fdn.ic........r................]-( 18849403920000) 0x7ffff7a62bca.1 CMP_P_I                   [  13219786]
[.................................................fdn.pic........r...............]-( 18849403920000) 0x7ffff7a62bca.2 CMP_P_I                   [  13219787]
[..................................................fdn.p.ic......r...............]-( 18849403920000) 0x7ffff7a62bca.3 CMP_P_I                   [  13219788]
[..................................................fdn.ic........r...............]-( 18849403920000) 0x7ffff7a62bd1.0 JZ_I                      [  13219789]
[..................................................fdn.ic........r...............]-( 18849403920000) 0x7ffff7a62bd1.1 JZ_I                      [  13219790]
[..................................................fdn.p..ic.....r...............]-( 18849403920000) 0x7ffff7a62bd1.2 JZ_I                      [  13219791]
[..............................................................f...dn.ic..r......]-( 18849403920000) 0x7ffff7a62bda.0 DEC_M                     [  13219831]
[..............................................................f...dn.p.ic..r....]-( 18849403920000) 0x7ffff7a62bda.1 DEC_M                     [  13219832]
[..............................................................f...dn.p..ic.r....]-( 18849403920000) 0x7ffff7a62bda.2 DEC_M                     [  13219833]
[..............................................................f...dn.ic....r....]-( 18849403920000) 0x7ffff7a62bdc.0 JZ_I                      [  13219834]
[..............................................................f...dn.ic....r....]-( 18849403920000) 0x7ffff7a62bdc.1 JZ_I                      [  13219835]
[..............................................................f...dn.p..ic.r....]-( 18849403920000) 0x7ffff7a62bdc.2 JZ_I                      [  13219836]
[ic.r........................................................................fdn.]-( 18849403920000) 0x7ffff7a62bf4.0 ADD_R_I                   [  13219874]
[pic..r......................................................................fdn.]-( 18849403920000) 0x7ffff7a62bf4.1 ADD_R_I                   [  13219875]
[ic...r......................................................................fdn.]-( 18849403920000) 0x7ffff7a62bf8.0 MOV_R_R                   [  13219876]
[p.ic...............r........................................................fdn.]-( 18849403920000) 0x7ffff7a62bfa.0 POP_R                     [  13219877]
[p.ic...............r........................................................fdn.]-( 18849403920000) 0x7ffff7a62bfa.1 POP_R                     [  13219878]
[p................ic..r......................................................fdn.]-( 18849403920000) 0x7ffff7a62bfa.2 POP_R                     [  13219879]
[p..ic................r......................................................fdn.]-( 18849403920000) 0x7ffff7a62bfb.0 POP_R                     [  13219880]
[p..ic................r......................................................fdn.]-( 18849403920000) 0x7ffff7a62bfb.1 POP_R                     [  13219881]
[.p.................ic..r.....................................................fdn]-( 18849403920000) 0x7ffff7a62bfb.2 POP_R                     [  13219882]
[.p..ic.................r.....................................................fdn]-( 18849403920000) 0x7ffff7a62bfc.0 POP_R                     [  13219883]
[.p..ic.................r.....................................................fdn]-( 18849403920000) 0x7ffff7a62bfc.1 POP_R                     [  13219884]
[.p..................ic.r.....................................................fdn]-( 18849403920000) 0x7ffff7a62bfc.2 POP_R                     [  13219885]
[.p...ic................r.....................................................fdn]-( 18849403920000) 0x7ffff7a62bfe.0 POP_R                     [  13219886]
[.p...ic................r.....................................................fdn]-( 18849403920000) 0x7ffff7a62bfe.1 POP_R                     [  13219887]
[.p..................ic.r.....................................................fdn]-( 18849403920000) 0x7ffff7a62bfe.2 POP_R                     [  13219888]
[n.p...ic...............r......................................................fd]-( 18849403920000) 0x7ffff7a62c00.0 RET_NEAR                  [  13219889]
[n.p...ic................r.....................................................fd]-( 18849403920000) 0x7ffff7a62c00.1 RET_NEAR                  [  13219890]
[n.p.................ic..r.....................................................fd]-( 18849403920000) 0x7ffff7a62c00.2 RET_NEAR                  [  13219891]
[....................................................fdn.ic.r....................]-( 18849404000000) 0x55555555477d.0 MOV_M_I                   [  13219896]
[....................................................fdn.pic.r...................]-( 18849404000000) 0x55555555477d.1 MOV_M_I                   [  13219897]
[....................................................fdn.ic..r...................]-( 18849404000000) 0x555555554784.0 JMP_I                     [  13219898]
[....................................................fdn.ic..r...................]-( 18849404000000) 0x555555554784.1 JMP_I                     [  13219899]
[....................................................fdn.pic.r...................]-( 18849404000000) 0x555555554784.2 JMP_I                     [  13219900]
[.......................................................fdn.ic.r.................]-( 18849404000000) 0x555555554793.0 CMP_M_I                   [  13219912]
[.......................................................fdn.ic..r................]-( 18849404000000) 0x555555554793.1 CMP_M_I                   [  13219913]
[.......................................................fdn.p.ic..r..............]-( 18849404000000) 0x555555554793.2 CMP_M_I                   [  13219914]
[.......................................................fdn.ic....r..............]-( 18849404000000) 0x555555554797.0 JLE_I                     [  13219915]
[.......................................................fdn.ic....r..............]-( 18849404000000) 0x555555554797.1 JLE_I                     [  13219916]
[.......................................................fdn.p..ic.r..............]-( 18849404000000) 0x555555554797.2 JLE_I                     [  13219917]
[...................................................................fdn.ic.r.....]-( 18849404000000) 0x555555554786.0 CALL_NEAR_I               [  13219935]
[...................................................................fdn.ic.r.....]-( 18849404000000) 0x555555554786.1 CALL_NEAR_I               [  13219936]
[...................................................................fdn.pic.r....]-( 18849404000000) 0x555555554786.2 CALL_NEAR_I               [  13219937]
[...................................................................fdn.ic..r....]-( 18849404000000) 0x555555554786.3 CALL_NEAR_I               [  13219938]
[...................................................................fdn.pic.r....]-( 18849404000000) 0x555555554786.4 CALL_NEAR_I               [  13219939]
[....fdn.ic.r....................................................................]-( 18849404080000) 0x5555555546fa.0 PUSH_R                    [  13219946]
[....fdn.ic.r....................................................................]-( 18849404080000) 0x5555555546fa.1 PUSH_R                    [  13219947]
[....fdn.pic.r...................................................................]-( 18849404080000) 0x5555555546fb.0 MOV_R_R                   [  13219948]
[..................fdn.ic.r......................................................]-( 18849404080000) 0x5555555546fe.0 SUB_R_I                   [  13219949]
[..................fdn.pic.r.....................................................]-( 18849404080000) 0x5555555546fe.1 SUB_R_I                   [  13219950]
[..................fdn.ic..r.....................................................]-( 18849404080000) 0x555555554702.0 MOV_R_M                   [  13219951]
[..................fdn.p.ic.r....................................................]-( 18849404080000) 0x55555555470b.0 MOV_M_R                   [  13219952]
[..................fdn.p.ic.r....................................................]-( 18849404080000) 0x55555555470f.0 XOR_R_R                   [  13219953]
[..................fdn.ic...r....................................................]-( 18849404080000) 0x555555554711.0 MOV_R_I                   [  13219954]
[..................fdn.ic...r....................................................]-( 18849404080000) 0x555555554718.0 MOV_R_I                   [  13219955]
[..................fdn.ic...r....................................................]-( 18849404080000) 0x55555555471f.0 SYSCALL_64                [  13219956]
[...................fdn.ic..r....................................................]-( 18849404080000) 0x55555555471f.1 SYSCALL_64                [  13219957]
[...................fdn.p.ic....r................................................]-( 18849404080000) 0x55555555471f.2 SYSCALL_64                [  13219958]
[...................fdn.ic......r................................................]-( 18849404080000) 0x55555555471f.3 SYSCALL_64                [  13219959]
[...................fdn.p..ic...r................................................]-( 18849404080000) 0x55555555471f.4 SYSCALL_64                [  13219960]
[...................fdn.ic......r................................................]-( 18849404080000) 0x55555555471f.5 SYSCALL_64                [  13219961]
[...................fdn.pic.....r................................................]-( 18849404080000) 0x55555555471f.6 SYSCALL_64                [  13219962]
[...................fdn.p.ic....r................................................]-( 18849404080000) 0x55555555471f.7 SYSCALL_64                [  13219963]
[...................fdn.p..ic...r................................................]-( 18849404080000) 0x55555555471f.8 SYSCALL_64                [  13219964]
[....................fdn.ic.....r................................................]-( 18849404080000) 0x55555555471f.9 SYSCALL_64                [  13219965]
[....................fdn.ic......r...............................................]-( 18849404080000) 0x55555555471f.10 SYSCALL_64                [  13219966]
[....................fdn.ic......r...............................................]-( 18849404080000) 0x55555555471f.11 SYSCALL_64                [  13219967]
[....................fdn.p..........ic.r.........................................]-( 18849404080000) 0x55555555471f.12 SYSCALL_64                [  13219968]
[.........................................fdn...ic.r.............................]-( 18849404080000) 0x55555555471f.13 SYSCALL_64                [  13220006]
[.........................................fdn...pic.r............................]-( 18849404080000) 0x55555555471f.14 SYSCALL_64                [  13220007]
[.........................................fdn...ic..r............................]-( 18849404080000) 0x55555555471f.15 SYSCALL_64                [  13220008]
[.........................................fdn...ic..r............................]-( 18849404080000) 0x55555555471f.16 SYSCALL_64                [  13220009]
[.........................................fdn...ic..r............................]-( 18849404080000) 0x55555555471f.17 SYSCALL_64                [  13220010]
[.........................................fdn...p......ic.r......................]-( 18849404080000) 0x55555555471f.18 SYSCALL_64                [  13220011]
[.........................................fdn...ic........r......................]-( 18849404080000) 0x55555555471f.19 SYSCALL_64                [  13220012]
[.........................................fdn...pic.......r......................]-( 18849404080000) 0x55555555471f.20 SYSCALL_64                [  13220013]
[..........................................f...dn.ic......r......................]-( 18849404080000) 0x55555555471f.21 SYSCALL_64                [  13220014]
[..........................................f...dn.pic.....r......................]-( 18849404080000) 0x55555555471f.22 SYSCALL_64                [  13220015]
[..........................................f...dn.p.ic....r......................]-( 18849404080000) 0x55555555471f.23 SYSCALL_64                [  13220016]
[..........................................f...dn.p..ic...r......................]-( 18849404080000) 0x55555555471f.24 SYSCALL_64                [  13220017]
[............................................f...dn.ic....r......................]-( 18849404080000) 0xffffffff81600010.0 SWAPGS                    [  13220018]
[............................................f...dn.ic.....r.....................]-( 18849404080000) 0xffffffff81600010.1 SWAPGS                    [  13220019]
[............................................f...dn.p.........ic.r...............]-( 18849404080000) 0xffffffff81600010.2 SWAPGS                    [  13220020]
[............................................f...dn.................p.ic.r.......]-( 18849404080000) 0xffffffff81600010.3 SWAPGS                    [  13220021]
[............................................f...dn.........................ic.r.]-( 18849404080000) 0xffffffff81600013.0 MOV_M_R                   [  13220022]
[............................................f...dn.........................ic.r.]-( 18849404080000) 0xffffffff8160001c.0 JMP_I                     [  13220023]
[............................................f...dn.........................ic.r.]-( 18849404080000) 0xffffffff8160001c.1 JMP_I                     [  13220024]
[............................................f...dn.........................pic.r]-( 18849404080000) 0xffffffff8160001c.2 JMP_I                     [  13220025]
[.............................................f...dn........................ic..r]-( 18849404080000) 0xffffffff81600030.0 MOV_R_M                   [  13220026]
[.............................................f...dn........................ic..r]-( 18849404080000) 0xffffffff81600039.0 PUSH_I                    [  13220027]
[r............................................f...dn........................p.ic.]-( 18849404080000) 0xffffffff81600039.1 PUSH_I                    [  13220028]
[r............................................f...dn........................p.ic.]-( 18849404080000) 0xffffffff81600039.2 PUSH_I                    [  13220029]
[r.............................................f..dn.........................ic..]-( 18849404080000) 0xffffffff8160003b.0 PUSH_M                    [  13220030]
[.r............................................f..dn.........................p.ic]-( 18849404080000) 0xffffffff8160003b.1 PUSH_M                    [  13220031]
[.r............................................f..dn.........................p.ic]-( 18849404080000) 0xffffffff8160003b.2 PUSH_M                    [  13220032]
[c.r...........................................f..dn.........................p..i]-( 18849404080000) 0xffffffff81600043.0 PUSH_R                    [  13220033]
[c.r...........................................f............................dn.pi]-( 18849404080000) 0xffffffff81600043.1 PUSH_R                    [  13220034]
[..r...........................................f............................dn.ic]-( 18849404080000) 0xffffffff81600045.0 PUSH_I                    [  13220035]
[ic.r..........................................f............................dn.p.]-( 18849404080000) 0xffffffff81600045.1 PUSH_I                    [  13220036]
[ic.r..........................................f............................dn.p.]-( 18849404080000) 0xffffffff81600045.2 PUSH_I                    [  13220037]
[.ic.r..........................................f...........................dn.p.]-( 18849404080000) 0xffffffff81600047.0 PUSH_R                    [  13220038]
[.ic.r..........................................f...........................dn.p.]-( 18849404080000) 0xffffffff81600047.1 PUSH_R                    [  13220039]
[..ic.r.........................................f...........................dn.p.]-( 18849404080000) 0xffffffff81600048.0 PUSH_R                    [  13220040]
[..ic.r.........................................f...........................dn.p.]-( 18849404080000) 0xffffffff81600048.1 PUSH_R                    [  13220041]
[...ic.r........................................f............................dn.p]-( 18849404080000) 0xffffffff81600049.0 PUSH_R                    [  13220042]
[...ic.r........................................f............................dn.p]-( 18849404080000) 0xffffffff81600049.1 PUSH_R                    [  13220043]
[....ic.r.......................................f............................dn.p]-( 18849404080000) 0xffffffff8160004a.0 PUSH_R                    [  13220044]
[....ic.r.......................................f............................dn.p]-( 18849404080000) 0xffffffff8160004a.1 PUSH_R                    [  13220045]
[.....ic.r.......................................f...........................dn.p]-( 18849404080000) 0xffffffff8160004b.0 PUSH_R                    [  13220046]
[.....ic.r.......................................f...........................dn.p]-( 18849404080000) 0xffffffff8160004b.1 PUSH_R                    [  13220047]
[......ic.r......................................f...........................dn.p]-( 18849404080000) 0xffffffff8160004c.0 PUSH_R                    [  13220048]
[......ic.r......................................f...........................dn.p]-( 18849404080000) 0xffffffff8160004c.1 PUSH_R                    [  13220049]
[.ic......r......................................f.............................dn]-( 18849404080000) 0xffffffff8160004d.0 PUSH_I                    [  13220050]
[.p.....ic.r.....................................f.............................dn]-( 18849404080000) 0xffffffff8160004d.1 PUSH_I                    [  13220051]
[.p.....ic.r.....................................f.............................dn]-( 18849404080000) 0xffffffff8160004d.2 PUSH_I                    [  13220052]
[.p......ic.r....................................f.............................dn]-( 18849404080000) 0xffffffff8160004f.0 PUSH_R                    [  13220053]
[.p......ic.r.....................................f............................dn]-( 18849404080000) 0xffffffff8160004f.1 PUSH_R                    [  13220054]
[.p.......ic.r....................................f............................dn]-( 18849404080000) 0xffffffff81600051.0 PUSH_R                    [  13220055]
[.p.......ic.r....................................f............................dn]-( 18849404080000) 0xffffffff81600051.1 PUSH_R                    [  13220056]
[.p........ic.r...................................f............................dn]-( 18849404080000) 0xffffffff81600053.0 PUSH_R                    [  13220057]
[n.p.......ic.r...................................f.............................d]-( 18849404080000) 0xffffffff81600053.1 PUSH_R                    [  13220058]
[n.p........ic.r..................................f.............................d]-( 18849404080000) 0xffffffff81600055.0 PUSH_R                    [  13220059]
[n.p........ic.r..................................f.............................d]-( 18849404080000) 0xffffffff81600055.1 PUSH_R                    [  13220060]
[n.p.........ic.r.................................f.............................d]-( 18849404080000) 0xffffffff81600057.0 PUSH_R                    [  13220061]
[n.p.........ic.r..................................f............................d]-( 18849404080000) 0xffffffff81600057.1 PUSH_R                    [  13220062]
[n.p..........ic.r.................................f............................d]-( 18849404080000) 0xffffffff81600058.0 PUSH_R                    [  13220063]
[n.p..........ic.r.................................f............................d]-( 18849404080000) 0xffffffff81600058.1 PUSH_R                    [  13220064]
[n.p...........ic.r................................f............................d]-( 18849404080000) 0xffffffff81600059.0 PUSH_R                    [  13220065]
[dn.p..........ic.r................................f.............................]-( 18849404080000) 0xffffffff81600059.1 PUSH_R                    [  13220066]
[dn.p...........ic.r...............................f.............................]-( 18849404080000) 0xffffffff8160005b.0 PUSH_R                    [  13220067]
[dn.p...........ic.r...............................f.............................]-( 18849404080000) 0xffffffff8160005b.1 PUSH_R                    [  13220068]
[dn.p............ic.r..............................f.............................]-( 18849404080000) 0xffffffff8160005d.0 PUSH_R                    [  13220069]
[dn.p............ic.r...............................f............................]-( 18849404080000) 0xffffffff8160005d.1 PUSH_R                    [  13220070]
[dn.p.............ic.r..............................f............................]-( 18849404080000) 0xffffffff8160005f.0 PUSH_R                    [  13220071]
[dn.p.............ic.r..............................f............................]-( 18849404080000) 0xffffffff8160005f.1 PUSH_R                    [  13220072]
[dn.ic...............r..............................f............................]-( 18849404080000) 0xffffffff81600061.0 XOR_R_R                   [  13220073]
[.dn.ic..............r..............................f............................]-( 18849404080000) 0xffffffff81600063.0 XOR_R_R                   [  13220074]
[.dn.pic.............r..............................f............................]-( 18849404080000) 0xffffffff81600065.0 XOR_R_R                   [  13220075]
[.dn.p.ic............r..............................f............................]-( 18849404080000) 0xffffffff81600068.0 XOR_R_R                   [  13220076]
[.dn.p..ic...........r..............................f............................]-( 18849404080000) 0xffffffff8160006b.0 XOR_R_R                   [  13220077]
[.dn.p...ic..........r...............................f...........................]-( 18849404080000) 0xffffffff8160006e.0 XOR_R_R                   [  13220078]
[.dn.p....ic..........r..............................f...........................]-( 18849404080000) 0xffffffff81600071.0 XOR_R_R                   [  13220079]
[.dn.p.....ic.........r..............................f...........................]-( 18849404080000) 0xffffffff81600073.0 XOR_R_R                   [  13220080]
[.dn.p......ic........r..............................f...........................]-( 18849404080000) 0xffffffff81600075.0 XOR_R_R                   [  13220081]
[..dn.p......ic.......r........................................................f.]-( 18849404080000) 0xffffffff81600078.0 XOR_R_R                   [  13220082]
[..dn.p.......ic......r........................................................f.]-( 18849404080000) 0xffffffff8160007b.0 XOR_R_R                   [  13220083]
[..dn.p........ic.....r.........................................................f]-( 18849404080000) 0xffffffff8160007e.0 XOR_R_R                   [  13220084]
[..dn.ic..............r.........................................................f]-( 18849404080000) 0xffffffff81600081.0 MOV_R_R                   [  13220085]
[..dn.p............ic.r.........................................................f]-( 18849404080000) 0xffffffff81600084.0 MOV_R_R                   [  13220086]
[..dn.ic...............r........................................................f]-( 18849404080000) 0xffffffff81600087.0 CALL_NEAR_I               [  13220087]
[..dn.ic...............r........................................................f]-( 18849404080000) 0xffffffff81600087.1 CALL_NEAR_I               [  13220088]
[..dn.p............ic..r........................................................f]-( 18849404080000) 0xffffffff81600087.2 CALL_NEAR_I               [  13220089]
[...dn.p...........ic..r........................................................f]-( 18849404080000) 0xffffffff81600087.3 CALL_NEAR_I               [  13220090]
[...dn.ic..............r........................................................f]-( 18849404080000) 0xffffffff81600087.4 CALL_NEAR_I               [  13220091]
[f..dn.p............ic.r.........................................................]-( 18849404160000) 0xffffffff81001e8d.0 PUSH_R                    [  13220092]
[f..dn.p............ic.r.........................................................]-( 18849404160000) 0xffffffff81001e8d.1 PUSH_R                    [  13220093]
[f..dn.p............ic.r.........................................................]-( 18849404160000) 0xffffffff81001e8e.0 MOV_R_R                   [  13220094]
[f..dn.p........ic......r........................................................]-( 18849404160000) 0xffffffff81001e91.0 STI                       [  13220095]
[f..dn.p.........ic.....r........................................................]-( 18849404160000) 0xffffffff81001e91.1 STI                       [  13220096]
[f..dn.p.........ic.....r........................................................]-( 18849404160000) 0xffffffff81001e91.2 STI                       [  13220097]
[f...dn.ic..............r........................................................]-( 18849404160000) 0xffffffff81001e91.3 STI                       [  13220098]
[f...dn.pic.............r........................................................]-( 18849404160000) 0xffffffff81001e91.4 STI                       [  13220099]
[.f..dn.p.ic............r........................................................]-( 18849404160000) 0xffffffff81001e91.5 STI                       [  13220100]
[.f..dn.p.........ic....r........................................................]-( 18849404160000) 0xffffffff81001e91.6 STI                       [  13220101]
[.f..dn.p..........ic...r........................................................]-( 18849404160000) 0xffffffff81001e91.7 STI                       [  13220102]
[.f..dn.ic...............r.......................................................]-( 18849404160000) 0xffffffff81001e91.18 STI                       [  13220103]
[.f..dn.p........ic......r.......................................................]-( 18849404160000) 0xffffffff81001e91.19 STI                       [  13220104]
[.f..dn.p....................ic.r................................................]-( 18849404160000) 0xffffffff81001e91.20 STI                       [  13220105]
[..f..dn...........................ic..r.........................................]-( 18849404160000) 0xffffffff81001e92.0 MOV_R_M                   [  13220106]
[..f..dn...........................p.ic..r.......................................]-( 18849404160000) 0xffffffff81001e9b.0 MOV_R_M                   [  13220107]
[..f..dn...........................ic....r.......................................]-( 18849404160000) 0xffffffff81001e9e.0 TEST_R_I                  [  13220108]
[..f..dn...........................p...ic.r......................................]-( 18849404160000) 0xffffffff81001e9e.1 TEST_R_I                  [  13220109]
[..f..dn...........................ic.....r......................................]-( 18849404160000) 0xffffffff81001ea3.0 JZ_I                      [  13220110]
[..f..dn...........................ic.....r......................................]-( 18849404160000) 0xffffffff81001ea3.1 JZ_I                      [  13220111]
[..f..dn...........................p....ic.r.....................................]-( 18849404160000) 0xffffffff81001ea3.2 JZ_I                      [  13220112]
[...f.dn...........................ic......r.....................................]-( 18849404160000) 0xffffffff81001eb0.0 CMP_R_I                   [  13220113]
[...f..dn...........................ic.....r.....................................]-( 18849404160000) 0xffffffff81001eb0.1 CMP_R_I                   [  13220114]
[...f..dn...........................ic.....r.....................................]-( 18849404160000) 0xffffffff81001eb7.0 JNBE_I                    [  13220115]
[...f..dn...........................ic.....r.....................................]-( 18849404160000) 0xffffffff81001eb7.1 JNBE_I                    [  13220116]
[...f..dn...........................pic....r.....................................]-( 18849404160000) 0xffffffff81001eb7.2 JNBE_I                    [  13220117]
[...f..dn...........................ic.....r.....................................]-( 18849404160000) 0xffffffff81001eb9.0 CMP_R_I                   [  13220118]
[...f..dn...........................pic....r.....................................]-( 18849404160000) 0xffffffff81001eb9.1 CMP_R_I                   [  13220119]
[....f.dn...........................p..ic...r....................................]-( 18849404160000) 0xffffffff81001ec0.0 SBB_R_R                   [  13220120]
[....f.dn...........................p...ic..r....................................]-( 18849404160000) 0xffffffff81001ec3.0 AND_R_R                   [  13220121]
[....f.............................dn.p..ic......................................]-( 18849404160000) 0xffffffff81001ec6.0 MOV_R_M                   [  13220122]
[.......................................................r........................]-( 18849404240000)     ...     
[....f.............................dn.p..ic......................................]-( 18849404160000) 0xffffffff81001ece.0 MOV_R_R                   [  13220123]
[.......................................................r........................]-( 18849404240000)     ...     
[....f.............................dn.ic.........................................]-( 18849404160000) 0xffffffff81001ed1.0 CALL_NEAR_I               [  13220124]
[.......................................................r........................]-( 18849404240000)     ...     
[....f.............................dn.ic.........................................]-( 18849404160000) 0xffffffff81001ed1.1 CALL_NEAR_I               [  13220125]
[.......................................................r........................]-( 18849404240000)     ...     
[....f.............................dn.pic........................................]-( 18849404160000) 0xffffffff81001ed1.2 CALL_NEAR_I               [  13220126]
[.......................................................r........................]-( 18849404240000)     ...     
[....f.............................dn.ic.........................................]-( 18849404160000) 0xffffffff81001ed1.3 CALL_NEAR_I               [  13220127]
[.......................................................r........................]-( 18849404240000)     ...     
[.....f............................dn.pic........................................]-( 18849404160000) 0xffffffff81001ed1.4 CALL_NEAR_I               [  13220128]
[.......................................................r........................]-( 18849404240000)     ...     
[......f...........................dn.p..........................................]-( 18849404160000) 0xffffffff81800b60.0 LFENCE                    [  13220129]
[............................................................ic.r................]-( 18849404240000)     ...     
[......f............................dn...........................................]-( 18849404160000) 0xffffffff81800b63.0 JMP_R                     [  13220130]
[..................................................................ic.r..........]-( 18849404240000)     ...     
[....................................................................fdn.ic.r....]-( 18849404320000) 0xffffffff810597d5.0 XOR_R_R                   [  13220186]
[....................................................................fdn.ic.r....]-( 18849404320000) 0xffffffff810597d7.0 MOV_R_I                   [  13220187]

```

### Arguing Correctness After Removing flags and making syscall execution more streamlined:
See the UGP report


