---
layout: post
date: 2018-08-22T18:17:46+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "algebra", "ideal", "polynomial", "gcd", "dp", "digit-dp" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc084/tasks/arc084_d" ]
redirect_from:
  - /writeup/algo/atcoder/arc-084-f/
---

# AtCoder Regular Contest 084: F - XorShift

## solution

多項式として整理しイデアルを使う。桁DP。計算量は $$d = \max(\log X, \log A_1, \log A_2, \dots, \log A_N)$$ とおいて $O(Nd^2)$。

各整数は多項式 $$X, A_1, A_2, \dots, A_N \in \mathbb{F} _ 2[x]$$ として見れる。
$2$倍する操作は $$f \in \mathbb{F} _ 2[x]$$ から $$xf$$ を作るような操作であり、xorの操作はそのまま加法である。
よって問題はideal $$I = (A_1, A_2, \dots, A_N)$$ を考え $$\mathrm{ans} = \# \left\{ f \in I \mid f \le X \right\}$$ を求めるものと言い換えられる。
ただしここで比較 $$\le$$ は整数として見てのもの。
体上の$1$変数多項式環はEuclid環であることを思い出せば、これはもちろん単項イデアル整域でもあるので $$I = (g)$$ であるような $$g \in \mathbb{F} _ 2[x]$$ が $$g = \mathrm{gcd}(A_1, A_2, \dots, A_N)$$ として一意に存在する。
よって求めるものは $$\mathrm{ans} = \# \left\{ a \in \mathbb{F} _ 2[x] \mid a g \le X \right\}$$ 。
これは $a$ の高次の係数から決めていく桁DPをすれば求まる。

## note

行列として整理しようとして破綻した。
editorialを覗いて「多項式」という単語が目に入ったとたんに解けた。
競プロの問題を代数学で殴るの楽しい。

## implementation

``` python
#!/usr/bin/env python3
def divmod(f, g):
    assert g
    h = 0
    for i in reversed(range(f.bit_length() - g.bit_length() + 1)):
        if f & (1 << (g.bit_length() + i - 1)):
            f ^= g << i
            h ^= 1 << i
    return h, f

def gcd(f, g):
    while g:
        q, r = divmod(f, g)
        f, g = g, r
    return f

import functools
def solve(n, x, a):
    # (g) = (a_1, ..., a_n) is a principal ideal since F_2[x] is a PID
    g = functools.reduce(gcd, a)

    # count h in F_2[x] s.t. h g <= x
    cnt = 0
    h = 0
    for k in reversed(range(x.bit_length() - g.bit_length() + 1)):
        bit = 1 << (g.bit_length() + k - 1)
        if (x & bit):
            cnt += 1 << k
        if (x & bit) != (h & bit):
            h ^= g << k
    cnt += (h <= x)
    return cnt % 998244353


def main():
    n, x = input().split()
    n = int(n)
    x = int(x, 2)
    a = [ int(input(), 2) for _ in range(n) ]
    print(solve(n, x, a))

if __name__ == '__main__':
    main()
```
