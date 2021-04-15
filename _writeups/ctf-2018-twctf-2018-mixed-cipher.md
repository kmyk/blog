---
redirect_from:
  - /writeup/ctf/2018/twctf-2018-mixed-cipher/
layout: post
date: 2018-09-04T06:11:12+09:00
tags: [ "ctf", "writeup", "twctf", "crypto", "aes", "rsa", "mersenne-twister", "prng-prediction", "lsb-leak-attack" ]
"target_url": [ "https://ctftime.org/task/6514" ]
---

# TokyoWesterns CTF 4th 2018: mixed cipher

## 解法

概要のみ

1.  RSA公開鍵 `pubkey` の $n$ : 算数
1.  AES秘密鍵 `aeskey` : LSB leak attack, [これ](https://kimiyuki.net/blog/2017/06/24/lsb-leak-attack/)を貼る
1.  AES IV : mersenne twisterの予測, [これ](https://github.com/kmyk/mersenne-twister-predictor)を貼る

## 実装

``` python
#!/usr/bin/env python3
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes, bytes_to_long
import gmpy2
import mt19937predictor  # https://github.com/kmyk/mersenne-twister-predictor

import argparse
import binascii
import fractions
import functools
import math
import random
import telnetlib

parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='crypto.chal.ctf.westerns.tokyo')
parser.add_argument('port', nargs='?', default=5643, type=int)
args = parser.parse_args()
tn = telnetlib.Telnet(args.host, args.port)

def encrypt(plaintext):
    tn.read_until(b'Welcome to mixed cipher :)')
    tn.write(b'1\n')
    tn.write(plaintext + b'\n')
    ciphertext = {}
    tn.read_until(b'RSA: ')
    ciphertext['RSA'] = binascii.unhexlify(tn.read_until(b'\n').rstrip())
    tn.read_until(b'AES: ')
    ciphertext['AES'] = binascii.unhexlify(tn.read_until(b'\n').rstrip())
    return ciphertext

def decrypt(ciphertext):
    tn.read_until(b'Welcome to mixed cipher :)')
    tn.write(b'2\n')
    tn.write(binascii.hexlify(ciphertext) + b'\n')
    tn.read_until(b'RSA: ')
    plaintext = binascii.unhexlify(tn.read_until(b'\n').rstrip())
    return { 'RSA': plaintext }

def print_flag():
    tn.read_until(b'Welcome to mixed cipher :)')
    tn.write(b'3\n')
    tn.read_until(b'here is encrypted flag :)\n')
    tn.read_until(b'\n')
    return binascii.unhexlify(tn.read_until(b'\n').rstrip())

def print_key():
    tn.read_until(b'Welcome to mixed cipher :)')
    tn.write(b'4\n')
    tn.read_until(b'here is encrypted key :)\n')
    return binascii.unhexlify(tn.read_until(b'\n').rstrip())

def find_n(e):
    m1 = 2
    m2 = 3
    c1 = bytes_to_long(encrypt(long_to_bytes(m1))['RSA'])
    c2 = bytes_to_long(encrypt(long_to_bytes(m2))['RSA'])
    return fractions.gcd(m1 ** e - c1, m2 ** e - c2)
e = 65537
n = find_n(e)
print('[*] n:', n)

def lsb_leak_attack(e, n, c):
    l, r = 0, n  # [l, r)
    i = 1
    while r - l >= 1:
        m = fractions.Fraction(l + r, 2)
        print('[*] m:', bin(math.ceil(m)))
        if bytes_to_long(decrypt(long_to_bytes(pow(2, i * e, n) * c % n))['RSA']) & 1:
            l = m
        else:
            r = m
        i += 1
    return math.ceil(l)
aeskey = print_key()
print('[*] encrypted AES key:', repr(aeskey))
aeskey = long_to_bytes(lsb_leak_attack(e, n, bytes_to_long(aeskey)))
print('[*] AES key:', repr(aeskey))

BLOCK_SIZE = 16
def guess_iv():
    predictor = mt19937predictor.MT19937Predictor()
    for _ in range(624 // 4):
        iv = encrypt(b'hoge')['AES'][: BLOCK_SIZE]
        print('[*] iv:', repr(iv))
        predictor.setrandbits(bytes_to_long(iv), BLOCK_SIZE * 8)
    return predictor.getrandbits(BLOCK_SIZE * 8)
iv = long_to_bytes(guess_iv())
print('[*] guessed iv:', repr(iv))
flag = print_flag()
print('[*] encrypted flag:', repr(flag))

# decrypt flag
aes = AES.new(aeskey, AES.MODE_CBC, iv)
flag = aes.decrypt(flag[BLOCK_SIZE :])
print('[*] flag:', repr(flag))
```
