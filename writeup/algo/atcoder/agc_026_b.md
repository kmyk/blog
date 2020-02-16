---
layout: post
date: 2018-08-10T00:31:20+09:00
tags: [ "competitive", "writeup", "atcoder", "agc", "gcd" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc026/tasks/agc026_b" ]
redirect_from:
  - /writeup/algo/atcoder/agc-026-b/
---

# AtCoder Grand Contest 026: B - rng_10s

## note

やればできそうなのに全然できなかったやつ。

## solution

数学。$B$を法として考えるのが重要。GCDを無視すれば$O(1)$。

他はeditorialにあるので省くが、次だけ示す: 任意の非負整数 $A \ge 0$ と正整数 $B, D \ge 1$ に対し $g = \mathrm{GCD}(B, D)$ とおくと $$\max \left\{ (A + kD) \bmod B \mid k \in \mathbb{Z} \right\} = B - g + (A \bmod g)$$ である。
証明。
$kD \in \mathbb{Z}/B\mathbb{Z}$ は常に $g = \mathrm{GCD}(B, D)$ の倍数であり、かつ $g$ の倍数 $k'g \in \mathbb{Z}/B\mathbb{Z}$ すべての上を動く。
このことさえ言ってしまえば $$(\text{左辺}) = \max \left\{ (A \bmod B) + kg \lt B \mid k \in \mathbb{Z} \right\}$$ は明らか。
$(A \bmod B) = qg + (A \bmod g)$ な $q \in \mathbb{Z}$ がとれるのでさらに $$\max \left\{ (A \bmod g) + kg \lt B \mid k \in \mathbb{Z} \right\}$$ とできる。
$(A \bmod g) \lt g$ であることから $g - (A \bmod g) \ge 1$。
よって $B - g + (A \bmod g) \lt B$ を満たす。
$(A + kD) \bmod g$ が一定であることから、もしこれより大きいものがあれば $(B - g + (A \bmod g)) + g \lt B$ であるはずだが、これは明らかに矛盾。
よって $B - g + (A \bmod g)$ が目的の最大値。

## implementation

``` python
#!/usr/bin/env python3
import fractions
def solve(a, b, c, d):
    if a < b:
        return False
    if d < b:
        return False
    if b <= c:
        return True
    assert c < b <= min(a, d)
    g = fractions.gcd(b, d)
    return b - g + a % g <= c

t = int(input())
for _ in range(t):
    a, b, c, d = map(int, input().split())
    ans = solve(a, b, c, d)
    print(['No', 'Yes'][ans])
```
