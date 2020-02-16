---
layout: post
redirect_from:
  - /blog/2017/09/20/csaw-quals-2017-another-xor/
date: "2017-09-20T20:33:18+09:00"
tags: [ "ctf", "writeup", "crypto", "csaw-ctf", "xor" ]
---

# CSAW Quals CTF 2017: Another Xor

EKOPARTYで忙しい + cryptoがほぼない なのでCSAWはほとんど手付かず。

## solution

xor典型。等式立てて満たすようにいい感じに復元する。
keyがけっこう長いことに注意。

## implementation

``` python
#!/usr/bin/env python3
import hashlib
import binascii

with open('encrypted') as fh:
    cipher = binascii.unhexlify(fh.read().rstrip())

def xor(s1, s2):
    return bytes(map(lambda a, b: a ^ b, s1, s2))

MD5_DIGEST_LENGTH = 32  # hexdigest
for len_key in range(1, 80):
    a = cipher[: - len_key - MD5_DIGEST_LENGTH]
    b = cipher[- len_key - MD5_DIGEST_LENGTH : - MD5_DIGEST_LENGTH]
    c = cipher[- MD5_DIGEST_LENGTH :]
    for key_0 in range(256):
        key = [ None ] * len_key
        key[0] = key_0
        for _ in range(len_key):
            for i in range(len_key):
                if key[i] is not None:
                    key[(i + len(a)) % len_key] = key[i] ^ b[i]
        if None in key:
            continue
        plaintext = xor(a, key * len(a))
        if b'flag' in plaintext:
            print(plaintext, bytes(key))
            raise
```
