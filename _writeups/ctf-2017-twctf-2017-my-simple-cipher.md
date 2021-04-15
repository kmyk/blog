---
layout: post
redirect_from:
  - /writeup/ctf/2017/twctf-2017-my-simple-cipher/
  - /blog/2017/09/04/twctf-2017-my-simple-cipher/
date: "2017-09-04T16:40:35+09:00"
tags: [ "ctf", "writeup", "twctf", "crypto" ]
---

# Tokyo Westerns CTF 3rd 2017: My Simple Cipher

本番では自明っぽかったのでやらずに放置したらnkhrlab氏がやってくれた。

## solution

等式 $\mathrm{encrypted}\_{i + 1} \equiv \mathrm{message}\_i + \mathrm{key}\_i + \mathrm{encrypted}\_i \pmod{128}$ を満たすように順に決めていけば決まる。

## implementation

``` python
#!/usr/bin/env python3

# params
encrypted = '7c153a474b6a2d3f7d3f7328703e6c2d243a083e2e773c45547748667c1511333f4f745e'
encrypted = bytes.fromhex(encrypted)
key     = bytearray(b'?????????????')
message = bytearray(b'TWCTF{??????????????}|?????????????')
assert 1 + len(message) == len(encrypted)

# solve
while ord('?') in message:
    for i in range(len(message) - 1):
        if message[i] != ord('?'):
            c = (encrypted[i + 1] - encrypted[i] - message[i]) % 128
            key[i % len(key)] = c
            message[len('TWCTF{??????????????}|') + i % len(key)] = c
        elif key[i % len(key)] != ord('?'):
            c = (encrypted[i + 1] - encrypted[i] - key[i % len(key)]) % 128
            message[i] = c

# check
for i in range(len(message)):
    assert encrypted[i + 1] == (message[i] + key[i % len(key)] + encrypted[i]) % 128

# output
print('key:', bytes(key).decode())
print('message:', bytes(message).decode())
```
