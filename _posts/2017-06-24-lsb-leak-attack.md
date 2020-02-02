---
category: blog
layout: post
date: "2017-06-24T03:50:46+09:00"
title: "LSB Leak Attackを実装した"
tags: [ "crypto", "binary-search", "rsa", "lsb-leak-attack" ]
---

## 概要

LSB Leak Attackとは、RSA暗号に対する次のような攻撃: 公開鍵$(e, n)$と任意の値に対する復号結果の偶奇を与える神託$f(x) = \mathrm{dec}(x) \bmod 2 = (x^d \bmod n) \bmod 2$が与えられているとき、任意の暗号文$c = \mathrm{enc}(m) = m^e \bmod n$から平文$m$を復号できる。以下のようなもの

1.  $\mathrm{enc}(k^ec) \equiv km \pmod{n}$であり特に$k = 2^i$を考える
2.  任意の$0 \le a \lt n$に対し$2a \bmod n$のLSBからは、この$2$倍する操作でoverflowしたかどうかの情報が得られる
3.  例えば$f(2^ec)$からは$m < \frac{n}{2}$の真偽が得られ、これにより二分探索できる

なお単にLSBの値を並べるのでは不足である。

## 詳細

まず$f( c) = m \bmod 2$である。
また、整数$k$に対し$\mathrm{enc}(km) = (km)^e \bmod n$は$k^ec \bmod n$として計算できる。
特に$k = 2$の時のため、$b = 2^e \bmod n$としておく。
$f(b^ic) = (2^im \bmod n) \bmod 2$である。

まず$i = 1$のとき。$f(bc) = (2m \bmod n) \bmod 2$。
$2m$は常に偶数、$n$は常に奇数、$0 \le m \lt n$より$0 \le m \lt 2n-2$なので、以下が言える。

-   $2m \bmod n$の偶奇$f(bc) = 1$の場合: $2m \bmod n = 2m - n$
-   $2m \bmod n$の偶奇$f(bc) = 0$の場合: $2m \bmod n = 2m$

これは$f(bc) = 1 \iff 2m \ge n$を意味する。
切り捨て誤差が出るので、有理数の不等式$\frac{n}{2} \le m$の形で持つ。

次に$i = 2$のとき。$f(b^2c) = (4m \bmod n) \bmod 2$。
同様に、

-   先程$f(bc) = 1$であった場合:
    -   $4m \bmod n$の偶奇$f(b^2c) = 1$の場合: $4m \bmod n = 2(2m \bmod n) \bmod n = (4m - 2n) \bmod n = (4m - 2n) - n = 4m - 3n$
    -   $4m \bmod n$の偶奇$f(b^2c) = 0$の場合: $4m \bmod n = 2(2m \bmod n) \bmod n = (4m - 2n) \bmod n = (4m - 2n) = 4m - 2n$
-   先程$f(bc) = 0$であった場合:
    -   $4m \bmod n$の偶奇$f(b^2c) = 1$の場合: $4m \bmod n = 4m - n$
    -   $4m \bmod n$の偶奇$f(b^2c) = 0$の場合: $4m \bmod n = 4m$

例えば $f(bc) = 1 \land f(b^2c) = 0 \iff 2n \le 4m \lt 3n$となる。
つまり$m \in [\frac{1}{2}n, \frac{3}{4}n)$。

このように繰り返していけば区間$[l, r)$が十分に縮まり$m \in [l, r)$を満たす$m$が唯一になる。そのような$m$として平文$m$が得られる。

## implementation

実装の注意としては、誤差を防ぐため区間の端点を有理数で持つこと。
整数で処理すると少しずれる。
またCPython組込みの`pow`は少し遅いので`gmpy2.powmod`を使うと速くなる。

``` python
# Python Version: 3.x
from fractions import Fraction
from math import ceil
from gmpy2 import powmod as pow  # fast

def attack(e, n, c, oracle):
    l, r = 0, n  # [l, r)
    i = 1
    while r - l >= 1:
        m = Fraction(l + r, 2)
        if oracle(pow(2, i * e, n) * c % n):
            l = m
        else:
            r = m
        i += 1
    return ceil(l)
```

``` python
# unittest
import Crypto.Util.number
import gmpy2
import random
e = 65537
p = Crypto.Util.number.getPrime(1024)
q = Crypto.Util.number.getPrime(1024)
n = p * q
d = int(gmpy2.invert(e, (p-1)*(q-1)))
m = random.randint(0, n-1)
c = pow(m, e, n)
oracle = lambda x: pow(x, d, n) % 2
assert attack(e, n, c, oracle) == m
```

## 参考資料

-   <https://crypto.stackexchange.com/questions/11053/rsa-least-significant-bit-oracle-attack>
-   <http://inaz2.hatenablog.com/entry/2016/11/09/220529>

---

-   追記: 2018年  6月 25日 月曜日 09:42:48 JST
    -   二分探索でなくて単にLSBの値を並べるのでは不足。$n$が$2$羃でない限りはoverflowの有無とbitの0/1は一致しないため
    -   `concurrent.futures` を用いた並列実行版は [ここ](/writeup/ctf/2018/google-ctf-quals-2018-perfect-secrecy/) にあります
-   追記: 2018年  7月  4日 水曜日 23:16:18 JST
    -   証明だけ書いており「つまり何？」みたいな話がなかったので追加
