---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/492/
  - /blog/2017/03/11/yuki-492/
date: "2017-03-11T00:11:06+09:00"
tags: [ "competitive", "writeup", "yukicoder", "experiment", "exponentiation-by-squaring" ]
"target_url": [ "http://yukicoder.me/problems/no/492" ]
---

# Yukicoder No.492 IOI数列

あまり考えずとりあえずpythonで実験したら$101010101010101010101$での規則性が出た。その後、残る$10^7$はよく見たらすぐだった。コードを書く前に考えるべきという感じがする。

## solution

$10^7$は行列にして繰り返し二乗法。$101010101010101010101$は規則性あるいは多倍長整数で殴る。$O(\log N)$。

繰り返し二乗法について、$$
\left( \begin{matrix}
a_N \\\\
1
\end{matrix} \right) = {\left( \begin{matrix}
100 & 1 \\\\
0 & 1
\end{matrix} \right)}^N \left( \begin{matrix}
0 \\\\
1
\end{matrix} \right)
$$ である。よって$O(\log N)$。

規則性について、$a_0 \equiv a\_{11} \equiv 0 \pmod{101010101010101010101}$である。$O(1)$。

## implementation

``` python
#!/usr/bin/env python3
def dgemm(f, g):
    h = [ [ 0, 0 ], [ 0, 0 ] ]
    for y in range(2):
        for x in range(2):
            for z in range(2):
                h[y][x] += f[y][z] * g[z][x]
            h[y][x] %= 1000000007
    return h
def dgemv(f, v):
    w = [ 0, 0 ]
    for y in range(2):
        for x in range(2):
            w[y] += f[y][x] * v[x]
        w[y] %= 1000000007
    return w
f = [ [   1, 0 ], [ 0, 1 ] ]
e = [ [ 100, 1 ], [ 0, 1 ] ]
n = int(input())
for i in range(len(bin(n))):
    if n & (1 << i):
        f = dgemm(f, e)
    e = dgemm(e, e)
print(dgemv(f, [ 0, 1 ])[0])
print(('10' * (n % 11))[:-1] or '0')
```
