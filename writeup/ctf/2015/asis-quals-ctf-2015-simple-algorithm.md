---
layout: post
redirect_from:
  - /blog/2016/08/31/asis-quals-ctf-2015-simple-algorithm/
date: "2016-08-31T17:31:55+09:00"
tags: [ "ctf", "writeup", "crypto", "asis-ctf", "greedy" ]
"target_url": [ "https://github.com/ctfs/write-ups-2015/tree/master/asis-quals-ctf-2015/crypto/simple-algorithm" ]
---

# ASIS Quals CTF 2015: Simple Algorithm

解けず。競プロぽい問題だったので解けるべきだった。

## solution

長さを割り出してから貪欲でよい。DPも思い付くが、怪しげな仮定がないと間に合わないので避けたい。
flagの形式が`ASIS\{[0-9a-f]+\}`というのは確認しておきたい。

$\mathrm{encode}(\mathrm{flag})$の値が分かっているので$\mathrm{flag} \in \mathrm{string}$を求める。
$\mathrm{encode}$は、文字列の先頭$1$文字を削除し、文字列を$16$進数変換を介して整数にし、$10$進数$2$桁ごとに切って関数$\mathrm{fan}\_3 : 100 \to \mathbb{N}$に通し、それぞれ結果を$10$進数展開してから文字列として結合する。

文字列の先頭$1$文字を削除は無視してよい。
文字列の長さ$l$を割り出したい。
$\mathrm{flag}$の先頭$5$文字は`ASIS{`であることが分かっているので、$16$進数変換後の整数は$\mathrm{int}(\text{ASIS\\{}) \cdot 256^{l-5}$にとても近いことが分かる。
関数$\mathrm{fan}\_3$による処理は先頭から局所的に行なうので、先頭部分はそのまま出てくる。
$l$を仮定し`ASIS{?????????????????`のようにして関数に通した結果の先頭部分は、後続の文字列の長さ$l-5$にのみ依存するので、これを全探索して一致する$l$が文字列の長さである。
`ASIS{`の次の$1$文字についても、同様に先頭部分の一致を考え、これが増加するような文字を貪欲に選んでいけばよい。

## implementation

``` python
#!/usr/bin/env python3
import binascii

def FAN(n, m):
    i = 0
    z = []
    s = 0
    while n > 0:
        if n % 2 != 0:
            z.append(2 - (n % 4))
        else:
            z.append(0)
        n = (n - z[i])//2
        i = i + 1
    z = z[::-1]
    l = len(z)
    for i in range(0, l):
        s += z[i] * m ** (l - 1 - i)
    return s

fan = [ None ] * 100 #=> str
for d in range(100):
    fan[d] = str(FAN(d, 3))

def encode(flag):
    hflag = binascii.hexlify(flag.encode())
    iflag = int(hflag[2:], 16)
    i = 0
    r = ''
    while i < len(str(iflag)):
        d = str(iflag)[i:i+2]
        nf = FAN(int(d), 3)
        r += str(nf)
        i += 2
    return r

def common_prefix(s, t):
    u = []
    for x, y in zip(s, t):
        if x == y:
            u += [ x ]
        else:
            break
    return ''.join(u)

def decode(enc, prefix='ASIS{', letter='0123456789abcdef', suffix='}'):
    filler = '?'
    length = 0
    fix = lambda s: prefix + s + (filler * (length - len(s))) + suffix
    score = lambda s: len(common_prefix(enc, encode(fix(s))))
    while score('') < len(prefix) * 2 * 0.6:
        length += 1
    print('length =', length)
    print('enc =', ' ' * (len(fix('')) - 6), enc)
    print(fix(''), encode(fix('')))
    s = []
    for _ in range(length):
        scores = []
        for c in letter:
            scores += [ score(''.join(s) + c) ]
            if len(s) + 1 == length:
                continue
            for d in letter:
                scores[-1] = max(scores[-1], score(''.join(s) + c + d))
        s += letter[scores.index(max(scores))]
        print(fix(''.join(s)), encode(fix(''.join(s))))
    assert encode(fix(''.join(s))) == enc
    return fix(''.join(s))

with open('enc.txt') as fh:
    enc = (fh.read().strip())
print(decode(enc))
```
