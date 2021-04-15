---
redirect_from:
  - /writeup/algo/yukicoder/718/
layout: post
date: 2018-07-28T01:40:18+09:00
tags: [ "competitive", "writeup", "yukicoder", "matrix", "exponentiation-by-squaring" ]
"target_url": [ "https://yukicoder.me/problems/no/718" ]
---

# Yukicoder No.718 行列のできるフィボナッチ数列道場 (1)

## solution

行列累乗やるだけ。$O(\log n)$。

関数 $$ \begin{pmatrix}
    F_{i+2}^2 \\ F_{i+2} F_{i+1} \\ F_{i+1}^2 \\ \sum_{j \le i + 1} F_j^2
\end{pmatrix} = F \begin{pmatrix}
    F_{i+1}^2 \\ F_{i+1} F_i \\ F_i^2 \\ \sum_{j \le i} F_j^2
\end{pmatrix} $$ は線形なので、これを$n$乗すればよい。

## implementation

numpyを上手く使うと楽

``` python
#!/usr/bin/env python3
import numpy as np

def powmod(f, n, mod):
    g = np.identity(4, dtype=np.uint64)
    for p in map(int, reversed(bin(n)[2 :])):
        if p:
            g = g * f % mod
        f = f * f % mod
    return g

def solve(n):
    # \begin{pmatrix} F_{i+1}^2 \\ F_{i+1} F_i \\ F_i^2 \\ \sum_{j \le i} F_j^2 \end{pmatrix}
    x = np.matrix([ 1, 0, 0, 0 ], dtype=np.uint64).transpose()
    f = np.matrix([
        [ 1, 2, 1, 0 ],
        [ 1, 1, 0, 0 ],
        [ 1, 0, 0, 0 ],
        [ 1, 0, 0, 1 ],
    ], dtype=np.uint64)
    mod = 10 ** 9 + 7
    return (powmod(f, n, mod) * x % mod)[3, 0]

print(solve(int(input())))
```
