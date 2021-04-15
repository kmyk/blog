---
layout: post
redirect_from:
  - /writeup/ctf/2017/hitb-gsec-2017-hack-in-the-card-i/
  - /blog/2017/08/29/hitb-gsec-2017-hack-in-the-card-i/
date: "2017-08-29T09:12:36+09:00"
tags: [ "ctf", "writeup", "crypto", "hitb-gsec", "rsa", "side-channel-attack" ]
---

# HITB GSEC Singapore 2017: HACK IN THE CARD I

このようにするというのは分かっていたが、本番では解けず。
writeup (<https://tradahacking.vn/hitb-gsec-singapore-2017-ctf-write-ups-crypto-category-803d6c770103>)を読んで追試した。

## problem

サイドチャネル攻撃をする問題。RSAの復号処理の際の電圧の波形が与えられるので秘密鍵を出せばよい。

## solution

[単純電力解析](https://ja.wikipedia.org/wiki/%E5%8D%98%E7%B4%94%E9%9B%BB%E5%8A%9B%E8%A7%A3%E6%9E%90)をする。
操作`pow(c, d, n)`が繰り返し二乗法による$O(\log d)$回の乗算で実現されているとする。
例えばコードは次のようになる。

```
def pow(c, d, n):
    m = 1
    i = 1
    while i <= d:
        if d & i:
            m = m * c % n
        c = c * c % n
        i <<= 1
    return m
```

乗算の実行が分かれば`if d & i:`で分岐がどうなったのか分かり、これから$d$が復元できる。

波形を離散的なデータに直すのはやるだけ。
そこから$d$を読みとるのはエスパー気味。
結論としては、波形のhigh/lowを`+`/`-`で書くとして`++-`ならif内が実行され`+-`ならそうでない。
先頭のいくらかは$d$に関与しないデータであるが、今回は残り全てが$d$の情報であった。
loopの形を見れば分かるが、最後に反転するのを忘れないようにする。

## implementation

``` python
#!/usr/bin/env python3

# read
with open('data.txt') as fh:
    data = list(map(float, fh.read().split()))
last = False
cnt = 0
wave = []
for i, y in enumerate(data):
    x = 0.001 * (i + 1)
    # print('#' * int(y - 150), y, x)
    ave = 0
    ave += (i - 1 >= 0 and data[i - 1] or data[i])
    ave += data[i]
    ave += (i + 1 < len(data) and data[i + 1] or data[i])
    ave /= 3
    cur = ave > 230
    if cur == last:
        cnt += 1
    else:
        # print('-+'[last], cnt)
        wave += [ '-+'[last] * round(cnt / 50) ]
        last = cur
        cnt = 0
wave += [ '-+'[last] * round(cnt / 50) ]
wave = ''.join(wave)
print(wave)

# decode
s = ''
i = 4
while i < len(wave):
    if wave[i : i + 3] == '++-':
        s += '1'
        i += 3
    else:
        assert wave[i : i + 2] == '+-'
        s += '0'
        i += 2
print(s)
d = int(s[:: -1], 2)

# check
import Crypto.PublicKey.RSA
import random
import gmpy2
with open('publickey.pem') as fh:
    key = Crypto.PublicKey.RSA.importKey(fh.read())
e = gmpy2.mpz(key.e)
n = gmpy2.mpz(key.n)
for _ in range(100):
    m = random.randint(0, n - 1)
    c = pow(m, e, n)
    assert pow(c, d, n) == m
print('d =', d)
```
