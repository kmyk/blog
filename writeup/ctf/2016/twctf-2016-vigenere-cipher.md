---
layout: post
redirect_from:
  - /blog/2016/09/05/twctf-2016-vigenere-cipher/
date: "2016-09-05T13:47:53+09:00"
tags: [ "ctf", "writeup", "crypto", "mmactf", "twctf", "vigenere-cipher" ]
"target_url": [ "https://score.ctf.westerns.tokyo/problems/25" ]
---

# Tokyo Westerns/MMA CTF 2nd 2016: Vigenere Cipher

(全部出るはずがbugにより)先頭blockの分の鍵しか出ないので困ってたら、そこからしほさんがguessing + known plaintext attackでflagを出してくれてプロだった。
すこしくやしい。
bugの原因は鍵長をbase64のblock長の倍数に揃えるのを忘れたことだった。

## solution

It is a Vigenere cipher with base64 encoding.
Use Kasiski test to detect the key length, and do exhaustive search for each base64 blocks.

## similar problems

-   <https://github.com/ctfs/write-ups-2015/tree/master/0ctf-2015/crypto/oldcrypto>

## implementation

``` python
#!/usr/bin/env python3
import functools
import math
import base64
import string
import sys
import logging
logging.basicConfig(stream=sys.stderr, level=logging.INFO)
log = logging.getLogger()

# from cipher.py
chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/'
assert len(chars) == 64
def shift(char, key, rev = False):
    if not char in chars or key == '?':
        return char
    if rev:
        return chars[(chars.index(char) - chars.index(key)) % len(chars)]
    else:
        return chars[(chars.index(char) + chars.index(key)) % len(chars)]
def decrypt(encrypted, key):
    return base64.b64decode(''.join([shift(c, key[i % len(key)], True) for i, c in enumerate(encrypted)]))

# encrypted.txt
with open('encrypted.txt') as fh:
    ciphertext = fh.read().strip()
log.info('encrypted.txt: %s', ciphertext)

# Kasiski test
def kasiski_test(s, l):
    dists = []
    for i in range(len(s) - l):
        word = s[i : i+l]
        j = s[i + l : ].find(word)
        if j != -1:
            dist = (i+l+j) - i
            dists += [ dist ]
    dist = functools.reduce(math.gcd, dists)
    return dist
dist = kasiski_test(ciphertext, 3)
log.info('estimated length: %d', dist)
assert dist == 12

# attack with the knowledge: base64-ed ascii
# $ echo -n AAAAAA | base64
# QUFBQUFB
# # 3 is the length of AAA
# # 4 is the length of QUFB
isascii = lambda s: all([ c < 128 for c in s ]) # for bytes
chunk = lambda s, l: [s[i:i+l] for i in range(0, len(s), l)]
assert dist % 4 == 0
def is_valid_key_block(key, k, restrict=3):
    key += 'A' * (4 - len(key))
    plaintext = decrypt(ciphertext, key)
    for s in chunk(plaintext, 3)[ k :: dist // 4]:
        if not isascii(s[ : restrict]):
            return False
    return True
for k in range(dist // 4):
    for x in chars:
        for y in chars:
            if not is_valid_key_block(x + y, k, restrict=1):
                continue
            for z in chars:
                if not is_valid_key_block(x + y + z, k, restrict=2):
                    continue
                for w in chars:
                    if is_valid_key_block(x + y + z + w, k):
                        key = x + y + z + w
                        plaintext = decrypt(ciphertext, key)
                        print(k, key, b'  '.join(chunk(plaintext, 3)[ k :: dist // 4]))

key = 'shA6I8HUXLFY'
print(key)
print(decrypt(ciphertext, key).decode())
# SKK is a Japanese Input Method developed by Sato Masahiko. Original SKK targets Emacs. However, there are various SKK programs that works other systems such as SKKFEP(for Windows), AquaSKK(for MacOS X) and eskk(for vim).
# OK, the flag is TWCTF{C14ss1caL CiPhEr iS v3ry fun}.
```
