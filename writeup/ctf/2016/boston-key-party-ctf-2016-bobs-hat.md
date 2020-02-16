---
layout: post
alias: "/blog/2017/06/22/boston-key-party-ctf-2016-bobs-hat/"
date: "2017-06-22T06:03:56+09:00"
tags: [ "ctf", "writeup", "crypto", "boston-key-party-ctf", "rsa", "wieners-attack" ]
"target_url": [ "https://github.com/ctfs/write-ups-2016/tree/master/boston-key-party-2016/crypto/bobs-hat-4" ]
---

# Boston Key Party CTF : bobs hat

雑に解いてしまった気がする。

ところで$p, q$が$\sqrt{n} \pm 1$になってたりするのを割るやつは[Fermat法](https://en.wikipedia.org/wiki/Fermat's_factorization_method)と名前が付いているらしい。ただのguessingだと認識してたから意外さがあった。

## problem

RSAを割る問題。$4$段階ある。

## solution

最初の$3$つはeshihoプロの[primefac-fork](https://github.com/elliptic-shiho/primefac-fork)に投げれば終わり。
最後の$1$つはそれではだめで、見ると$e$が大きいのでWiener's attack。[owiener](https://github.com/orisano/owiener)が便利だった。

## implementation

``` python
#!/usr/bin/env python3
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('n', type=int)
args = parser.parse_args()

from Crypto.PublicKey import RSA
import primefac
import owiener
import gmpy2
with open('almost_' * args.n + 'there.pub') as fh:
    key = RSA.importKey(fh.read())

if args.n != 1:
    p, q = primefac.primefac(key.n)
    d = int(gmpy2.invert(key.e, (p-1)*(q-1)))
else:
    d = owiener.attack(key.e, key.n)
key = RSA.construct((key.n, key.e, d))


with open('almost_' * args.n + 'there.encrypted') as fh:
    print(key.decrypt(fh.buffer.read()).decode())
```
