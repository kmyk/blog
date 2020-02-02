---
layout: post
alias: "/blog/2017/03/22/0ctf-2017-integrity/"
date: "2017-03-22T16:51:59+09:00"
title: "0ctf 2017: integrity"
tags: [ "ctf", "writeup", "0ctf", "crypto", "block-cipher", "cbc-mode" ]
---

## problem

user名を渡すとtokenが帰ってきて、そのtokenを渡すとそのuser名でloginできる。
`admin`のtokenは要求しても弾かれるが、なんとかして`admin`としてloginする問題。

鯖のコードは与えられる。

```
$ nc 202.120.7.217 8221
Welcome to 0CTF encryption service!
Please [r]egister or [l]ogin
r
foo
Here is your secret:
b628cd3ad03bfbc19118f25ab2afa88cd9bf56fbc52c67dfe68d13422bcadbee144a2878139d901d086557b206906c9b
Please [r]egister or [l]ogin
l
b628cd3ad03bfbc19118f25ab2afa88cd9bf56fbc52c67dfe68d13422bcadbee144a2878139d901d086557b206906c9b
Welcome foo!
Please [r]egister or [l]ogin
r
admin
You cannot use this name!
```

## solution

`md5(pad("admin")) + pad("admin")`を投げて先頭$1$blockを削って投げ返すだけ。

読むと主に以下が分かる。

-   tokenの先頭にivが付与されている
-   decrypt後の先頭blockが残りの部分のmd5sumでなければならない

ここでWikipediaにある以下の図を眺めれば分かる。

![](/blog/2017/03/22/0ctf-2017-integrity/CBC_decryption.svg)

## implementation

``` python
#!/usr/bin/env python2
from hashlib import md5

from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='202.120.7.217')
parser.add_argument('port', nargs='?', default=8221, type=int)
parser.add_argument('--log-level', default='debug')
args = parser.parse_args()
context.log_level = args.log_level

p = remote(args.host, args.port)
def register(name):
    p.recvuntil('Please [r]egister or [l]ogin\n')
    p.sendline('r')
    p.sendline(name)
    p.recvuntil('Here is your secret:\n')
    secret = p.recvline(keepends=False)
    log.info('register %s: %s', name, secret)
    return secret
def login(secret):
    p.recvuntil('Please [r]egister or [l]ogin\n')
    p.sendline('l')
    p.sendline(secret)
    p.recvuntil('Welcome admin!\n')
    flag = p.recvline(keepends=False)
    log.info('flag: %s', flag)

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
chunk = lambda s, l: [ s[i : i+l] for i in range(0, len(s), l) ]

data = pad('admin')
checksum = md5(data).digest()
secret = register(checksum + data)
_, pseudo_iv, a, b = chunk(secret, 2*BS)
payload = ''.join([ pseudo_iv, a, b ])

login(payload)
```

```
$ ./a.py
[+] Opening connection to 202.120.7.217 on port 8221: Done
[DEBUG] Received 0x23 bytes:
    'Welcome to 0CTF encryption service!'
[DEBUG] Received 0x1e bytes:
    '\n'
    'Please [r]egister or [l]ogin\n'
[DEBUG] Sent 0x2 bytes:
    'r\n'
[DEBUG] Sent 0x21 bytes:
    00000000  21 8e 2a b7  9d 1e f7 18  cc 84 a4 72  45 0b a8 8f  │!·*·│····│···r│E···│
    00000010  61 64 6d 69  6e 0b 0b 0b  0b 0b 0b 0b  0b 0b 0b 0b  │admi│n···│····│····│
    00000020  0a                                                  │·│
    00000021
[DEBUG] Received 0x14 bytes:
    'Here is your secret:'
[DEBUG] Received 0x9f bytes:
    '\n'
    '01724b88b08e1e9ac9888f6be04e63c96309faf3e3ddad4833e2464a3e206fc7df3cbd50bed9474075ffedad1515d78a433ff5c3e4a8c889588cb52ac3736272\n'
    'Please [r]egister or [l]ogin\n'
[*] register !\x8e*\xb7\x9d\x1e�̄\xa4rE\x0b\xa8\x8fadmin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b: 01724b88b08e1e9ac9888f6be04e63c96309faf3e3ddad4833e2464a3e206fc7df3cbd50bed9474075ffedad1515d78a433ff5c3e4a8c889588cb52ac3736272
[DEBUG] Sent 0x2 bytes:
    'l\n'
[DEBUG] Sent 0x61 bytes:
    '6309faf3e3ddad4833e2464a3e206fc7df3cbd50bed9474075ffedad1515d78a433ff5c3e4a8c889588cb52ac3736272\n'
[DEBUG] Received 0xe bytes:
    'Welcome admin!'
[DEBUG] Received 0x53 bytes:
    '\n'
    'flag{Easy_br0ken_scheme_cann0t_keep_y0ur_integrity}\n'
    '\n'
    'Please [r]egister or [l]ogin\n'
[*] flag: flag{Easy_br0ken_scheme_cann0t_keep_y0ur_integrity}
[*] Closed connection to 202.120.7.217 port 8221
```
