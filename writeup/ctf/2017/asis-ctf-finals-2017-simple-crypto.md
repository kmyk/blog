---
layout: post
alias: "/blog/2017/09/11/asis-ctf-finals-2017-simple-crypto/"
title: "ASIS CTF Finals 2017: Simple Crypto"
date: "2017-09-11T08:09:00+09:00"
tags: [ "ctf", "writeup", "crypto", "asis-ctf" ]
---

最初はげきむずだったのでz3など色々試していたのに、消えて戻ってきたら自明問になっていました。

## solution

xor.

## implementation

``` python
#!/usr/bin/env python2
import sys
def xor_str(x, y):
    if len(x) > len(y):
        return ''.join([chr(ord(z) ^ ord(p)) for (z, p) in zip(x[:len(y)], y)])
    else:
        return ''.join([chr(ord(z) ^ ord(p)) for (z, p) in zip(x, y[:len(x)])])

KEY = 'musZTXmxV58UdwiKt8Tp'
key = KEY.encode('hex')
with open('flag.enc') as fh:
    enc = fh.read()

print xor_str(enc, key * len(enc)).decode('hex')  #=> PNG
```
