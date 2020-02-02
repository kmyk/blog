---
layout: post
alias: "/blog/2018/03/26/volgactf-2018-quals-forbidden/"
title: "VolgaCTF 2018 Quals: Forbidden"
date: "2018-03-26T00:00:02+09:00"
tags: [ "ctf", "writeup", "volgactf", "crypto", "aes", "gcm-mode" ]
"target_url": [ "https://quals.2018.volgactf.ru/tasks" ]
---

## problem

AES-[GCM](https://ja.wikipedia.org/wiki/Galois/Counter_Mode) による暗号文/署名がいくつか与えられる。
ただしIVの使い回しがある。
署名で欠けているものがあるのでこれを復元せよ。

## solution

[本当は怖いAES-GCMの話 - ぼちぼち日記](http://d.hatena.ne.jp/jovi0608/20160524/1464054882) に書いてあるのをすればよい

## note

GCM-modeを知らなかったのでメモ:

-   入力は平文$M$とassociated data $A$の対
-   出力は暗号文$C$と署名$T$の対
-   TLSではとりあえずこれ使っておけば安心、といった位置の暗号ぽい
    -   例: 手元のFirefoxが`google.co.jp`に対して`Connection Encrypted (TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, 128 bit keys, TLS 1.2)`
-   式は複雑だが一度追えば分かる
    -   平文$D$ associated data $A$を$16$byteごとのblock $D\_1, \dots, D\_{l\_D}$と$A\_1, \dots, A\_{l\_A}$に切る。仕組み上paddingは不要
    -   AESの共通鍵$K$を使って暗号文$C\_i = D\_i + \mathrm{enc}\_K(IV + i + 1)$
    -   署名$T$に関して:
        -   有限体 $GF(2^{128})$ の上で計算
        -   $K$から$\mathrm{enc}\_K(0)$として定まる値$H$がGCM-modeの鍵1
        -   $K, IV$から$\mathrm{enc}\_K(IV + 1)$として定まる値$S$がGCM-modeの鍵2
        -   $\newcommand\doubleplus{+\kern-1.3ex+\kern0.8ex}$ 署名$T = A\_1 H^{l\_A+l\_D+3}  + \dots + A\_{l\_A} H^{l\_D+3}  + D\_1 H^{l\_D+2} + \dots + D\_{l\_D} H^2 + (l\_D \doubleplus l\_A) H + S$

他:

-   解けたはずなんだけど答えが合わないので見てほしいと @h\_noson に投げたらバグを見つけてくれた。助かる

## implementation

``` python
#!/usr/bin/env sagemath
from sage.all import *

# http://mslc.ctf.su/wp/boston-key-party-ctf-2016-gcm-crypto-9pts-2/

def tobin(x, n):
    x = Integer(x)
    nbits = x.nbits()
    assert nbits <= n
    return [0] * (n - nbits) + x.bits()[:: -1]

def frombin(v):
    return int("".join(map(str, v)), 2)

X = GF(2).polynomial_ring().gen()
poly = X ** 128 + X ** 7 + X ** 2 + X ** 1 + 1
F = GF(2 ** 128, name='a', modulus=poly)

def toF(x):
    # Little endian, so need bit reverse
    x = frombin(tobin(x, 128)[:: -1])
    return F.fetch_int(x)

def fromF(x):
    # Little endian, so need bit reverse
    x = x.integer_representation()
    x = frombin(tobin(x, 128)[:: -1])
    return x


# known
A1 = 'John Doe'
A2 = 'VolgaCTF'
A3 = 'John Doe'
(C1, T1) = ('1761e540522379aab5ef05eabc98516fa47ae0c586026e9955fd551fe5b6ec37e636d9fd389285f3', '0674d6e42069a10f18375fc8876aa04d')
(C2, T2) = ('1761e540522365aab1e644ed87bb516fa47ae0d9860667d852c6761fe5b6ec37e637c7fc389285f3', 'cf61b77c044a8fb1566352bd5dd2f69f')
C3 = '1761e540522379aab5ef05eabc98516fa47ae0d9860667d852c6761fe5b6ec37e646a581389285f3'

LEN = toF(int('%016x%016x' % (len(A1), len(C1)), 16))
A1 = toF(int(A1.encode('hex').ljust(32, '0'), 16))
A2 = toF(int(A2.encode('hex').ljust(32, '0'), 16))
A3 = toF(int(A3.encode('hex').ljust(32, '0'), 16))
C1 = map(lambda s: toF(int(s, 16)), [ C1[: 32], C1[32 : 64], C1[64 :].ljust(32, '0') ])
C2 = map(lambda s: toF(int(s, 16)), [ C2[: 32], C2[32 : 64], C2[64 :].ljust(32, '0') ])
C3 = map(lambda s: toF(int(s, 16)), [ C3[: 32], C3[32 : 64], C3[64 :].ljust(32, '0') ])
T1 = toF(int(T1, 16))
T2 = toF(int(T2, 16))

R.<x> = PolynomialRing(F)
D1 = A1 + A2
D2 = C1[0] + C2[0]
D3 = C1[1] + C2[1]
D4 = C1[2] + C2[2]
for root, k in (D1 * x ** 5 +    D2 * x ** 4 +    D3 * x ** 3 +    D4 * x ** 2 + (T1 + T2)).roots():
    assert k == 1
    H = root
    S         = A1 * H ** 5 + C1[0] * H ** 4 + C1[1] * H ** 3 + C1[2] * H ** 2 + LEN * H + T1
    assert S == A2 * H ** 5 + C2[0] * H ** 4 + C2[1] * H ** 3 + C2[2] * H ** 2 + LEN * H + T2
    T3        = A3 * H ** 5 + C3[0] * H ** 4 + C3[1] * H ** 3 + C3[2] * H ** 2 + LEN * H + S
    print '%032x' % fromF(T3)
```
