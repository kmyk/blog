---
layout: post
title: "Google Capture The Flag 2018 (Quals): perfect secrecy"
date: "2018-06-25T11:39+09:00"
tags: [ "ctf", "writeup", "google-ctf", "crypto", "rsa", "lsb-leak-attack" ]
"target_url": [ "https://ctftime.org/event/623" ]
---

## solution

ちょっと変形するとLSB oracleが得られるのでやるだけ。
過去に書いたやつをコピペ: <https://kimiyuki.net/blog/2017/06/24/lsb-leak-attack/>

## note

まったくの自明問なのに落とした。 終了10分後にflagが出た。
敗因はflagの先頭のpaddingで、ここがbinaryなので失敗と判断して最後まで見なかったことで遅れてしまった。

## implementation

``` python
#!/usr/bin/env python3
import argparse
import concurrent.futures
import fractions
import math
import socket

from Crypto.Util.number import long_to_bytes, bytes_to_long
import Crypto.PublicKey.RSA as RSA

parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='perfect-secrecy.ctfcompetition.com')
parser.add_argument('port', nargs='?', type=int, default=1337)
parser.add_argument('--flag', default='flag.txt')
parser.add_argument('--pubkey', default='key_pub.pem')
args = parser.parse_args()

print('[+] read', args.flag)
with open(args.flag, 'rb') as fh:
    ciphertext = fh.read()
print('[*] size =', len(ciphertext))

print('[+] read', args.pubkey)
with open(args.pubkey) as fh:
    public_key = RSA.importKey(fh.read())
print('[*] n =', public_key.n)
print('[*] e =', public_key.e)
print('[*] size =', public_key.size())

def challenge(m0, m1, ciphertext):
    assert m0 in [ 0, 1 ]
    assert m1 in [ 0, 1 ]
    assert len(ciphertext) == (public_key.size() + 1) // 8
    print('[+] connect', args.host, args.port)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((args.host, args.port))
        sock.send(bytes([ m0 ]))
        sock.send(bytes([ m1 ]))
        sock.send(ciphertext)
        for _ in range(100):
            yield ord(sock.recv(1))

def lsb_oracle(c):
    cnt = 0
    for p in challenge(0, 1, long_to_bytes(c, 128)):
        cnt += p
    return int(cnt >= 50)

n = public_key.n
e = public_key.e
c = bytes_to_long(ciphertext)

def attack(e, n, c, oracle, max_workers=16):
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {}
        for i in range(1, n.bit_length() + 10):
            futures[i] = executor.submit(oracle, pow(2, i * e, n) * c % n)
        l, r = 0, n  # [l, r)
        i = 1
        while r - l >= 1:
            m = fractions.Fraction(l + r, 2)
            if futures[i].result():
                l = m
            else:
                r = m
            i += 1
            print('[*] l =', long_to_bytes(math.floor(l)))
            print('[*] r =', long_to_bytes(math.ceil(r)))
        return math.ceil(l)

m = attack(e, n, c, lsb_oracle)
assert pow(m, e, n) == c
print('[*] plaintext = ', long_to_bytes(m))
```
