---
layout: post
alias: "/blog/2017/06/22/google-ctf-2017-quals-crypto-backdoor/"
date: "2017-06-22T03:01:10+09:00"
tags: [ "ctf", "writeup", "crypto", "google-ctf", "group", "chinese-remainder-theorem" ]
---

# Google Capture The Flag 2017 (Quals): Crypto Backdoor

## problem

独自の公開鍵暗号の実装 `crypto_backdoor.py` が与えられるのでflagを割る問題。

## solution

与えられた`crypto_backdoor.py`の関数について:

-   `I`, `Sn` は文字列 $\leftrightarrow$ 整数の変換/逆変換
-   `egcd`, `modinv` は通常のもの
-   `double`, `encrypt` は見たまま
-   `mul` は `add` を繰り返し二乗法で$m$回適用する
-   `add`は剰余群$\mathbb{Z}/p\mathbb{Z}$の直積の上でなにやら(除算込みの)演算をしている

ここで $A, g, p$が与えられているので$A = \mathrm{mul}(m, g, p)$なる$m$を求められればよい。
つまり除算をしたい。

ここで$p$は素数ではなく、ある程度小さい異なる素数の積に分解できる (<http://factordb.com/index.php?query=606341371901192354470259703076328716992246317693812238045286463>)。
よって群論の文脈での中華剰余定理 ($m, n \ge 1$が互いに素なら$\mathbb{Z}/mn\mathbb{Z} \cong \mathbb{Z}/m\mathbb{Z} \times \mathbb{Z}/n\mathbb{Z}$) を使って、各巡回群ごとに独立に計算できる。
素因数の大きさが$10^9$程度なので、これは全探索による逆関数の計算が可能。
それぞれで$m\_i$を求めれば、$\mathrm{mul}(p, g, p) = g$であることが発見できるのでこれを利用し中華剰余定理で目標の$m$を復元できる。

注意としては`add`では無理矢理に逆元を取っているので、例えば単位元に相当するものが存在できない (なので無理矢理$-1$として足している)。このあたりを考慮して丁寧に実装しないとバグる。実際、flagは取ったが使った実装はまだバグが埋まってるように見える。$A$から$\mathrm{aliceSecret}$を復元するのは動いたが、同様に動くはずの$B$から$\mathrm{bobSecret}$が出てくれない。

`CTF{Anyone-can-make-bad-crypto}`

## implementation

``` python
#!/usr/bin/env python2
import sys
import operator
import functools
import subprocess
import gmpy2
from crypto_backdoor import *

def crt(eqn1, eqn2):
    x1, m1 = eqn1
    x2, m2 = eqn2
    d = int(gmpy2.gcd(m1, m2))
    x = x1 + (m1 // d) * (x2 - x1) * int(gmpy2.invert(m1 // d, m2 // d))
    m = int(gmpy2.lcm(m1, m2))
    return x % m, m

def div(a, g, p):
    if a == g:
        return 1
    # known = [
    #     24598024,
    #     71971632,
    #     73353382,
    #     97096718,
    #     111512372,
    #     147499822,
    #     217014904,
    #     418335728,
    #     445387078,
    #     468722272,
    #     749957078,
    #     793852246,
    #     927343918,
    #     934896152,
    # ]
    # for m in known:
    #     if mul(m, g, p) == a:
    #         return m
    proc = subprocess.Popen([ './a.out' ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=sys.stderr)
    s = ''
    s += '%d %d\n' % a
    s += '%d %d\n' % g
    s += '%d\n' % p
    s, _ = proc.communicate(s)
    m = int(s)
    assert mul(m, g, p) == a
    return m

# http://factordb.com/index.php?query=606341371901192354470259703076328716992246317693812238045286463
factors = [
    901236131,
    911236121,
    921236161,
    931235651,
    941236273,
    951236179,
    961236149,
]
assert p == functools.reduce(operator.mul, factors)

# solve in the small spaces
eqns = []
for p0 in factors:
    g0 = (g[0] % p0, g[1] % p0)
    A0 = (A[0] % p0, A[1] % p0)
    assert mul(p0, g0, p0) == g0
    m = div(A0, g0, p0)
    assert mul(m, g0, p0) == A0
    assert mul(m + p0-1, g0, p0) == A0
    eqns += [ ( m, p0-1 ) ]

# reconstruct the secret using CRT
m, _ = functools.reduce(crt, eqns)
print('aliceSecret', m)
aliceSecret = m
assert A == mul(aliceSecret, g, p)

# decode flag
aliceMS = mul(aliceSecret, B, p)
masterSecret = aliceMS[0] * aliceMS[1]
length = 31
encrypted_message = 137737300119926924583874978524079282469973134128061924568175107915062758827931077214500356470551826348226759580545095568667325
flag = Sn(encrypted_message ^ masterSecret, length)
print('flag', flag)
assert length == len(flag)
assert encrypted_message == I(flag) ^ masterSecret
```

``` c++
#include <cassert>
#include <cstdio>
#include <tuple>
using ll = long long;
using namespace std;

inline int modadd(int a, int b, int mod) { int c = a + b; return c < mod ? c : c - mod; }
inline int modsub(int a, int b, int mod) { int c = a - b; return c >= 0 ? c : c + mod; }

pair<int, int> extgcd(int a, int b) {
    if (b == 0) return { 1, 0 };
    int na, nb; tie(na, nb) = extgcd(b, a % b);
    return { nb, na - a/b * nb };
}
int modinv(int a, int n) { // a and n must be relatively prime, O(log n)
    assert (1 <= a and a < n);
    return modsub(extgcd(a, n).first % n, 0, n);
}

struct point { int x, y; };
bool operator != (point const & a, point const & b) {
    return a.x != b.x or a.y != b.y;
}
struct zero_exception {};
point add(point const & a, point const & b, int p) {
    int a_z = modsub(a.x, a.y, p);
    int b_z = modsub(b.x, b.y, p);
    ll denom = modsub(modadd(a_z, b_z, p), 1, p);
    if (denom == 0) {
        throw zero_exception {};
    }
    ll denom_inv = modinv(denom, p);
    ll c_z = a_z *(ll) b_z % p * denom_inv % p;
    ll c_y = a.y *(ll) b.y % p * denom_inv % p;
    return { modadd(c_z, c_y, p), int(c_y) };
}

int main() {
    point a; scanf("%d%d", &a.x, &a.y);
    point g; scanf("%d%d", &g.x, &g.y);
    int p; scanf("%d", &p);
fprintf(stderr, "a = (%d, %d)\n", a.x, a.y);
fprintf(stderr, "g = (%d, %d)\n", g.x, g.y);
fprintf(stderr, "p = %d\n", p);
fprintf(stderr, "find the m such that a = mg\n");
    point b = g;
    ll m = 1;
    while (b != a) {
if (m % 10000000 == 0) fprintf(stderr, "trying %lld...\n", m);
        try {
            b = add(b, g, p);
            ++ m;
        } catch (zero_exception) {
            b = add(b, add(g, g, p), p);
            m += 2;
        }
        assert (0 <= b.x and b.x < p);
        assert (0 <= b.y and b.y < p);
        assert (m < p);
    }
fprintf(stderr, "found m = %lld\n", m);
    printf("%lld\n", m);
    return 0;
}
```
