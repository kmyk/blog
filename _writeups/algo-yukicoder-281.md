---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/281/
  - /blog/2016/06/14/yuki-281/
date: 2016-06-14T21:36:51+09:00
tags: [ "competitive", "writeup", "yukicoder", "implementation" ]
"target_url": [ "http://yukicoder.me/problems/661" ]
---

# Yukicoder No.281 門松と魔法(1)

とても嫌らしい問題。実装に丁寧さが必要。

## solution

-   $3$つの数値で、真ん中が最も低い/高いで場合分けする。
-   $a \ge b$から$a$を減らして$a - kd \lt b$にぎりぎりでするには$k = \lceil \frac{a - b-1}{d} \rceil$。
-   $d = 0$のときや$h_1 = h_3$のときに注意。
-   適当に$-3 \dots +3$をして誤魔化す or 丁寧に実装。

## implementation

``` python
#!/usr/bin/env python3
d = int(input())
h1 = int(input())
h2 = int(input())
h3 = int(input())
def is_kadomatsu(a, b, c):
    assert a >= 0 and b >= 0 and c >= 0
    return a != c and ((a < b and b > c) or (a > b and b < c))
def make_lt(a, b):
    if b == 0:
        return float('inf')
    else:
        return max(0, (a - (b-1) + d-1) // d)
def check_count(k1, k2, k3):
    if k1 < 0 or k2 < 0 or k3 < 0:
        return float('inf')
    g1 = max(0, h1 - k1 * d)
    g2 = max(0, h2 - k2 * d)
    g3 = max(0, h3 - k3 * d)
    if is_kadomatsu(g1, g2, g3):
        return k1 + k2 + k3
    else:
        return float('inf')
if d == 0:
    if is_kadomatsu(h1, h2, h3):
        ans = 0
    else:
        ans = -1
else:
    ans = float('inf')
    k1 = make_lt(h1, h2)
    k2 = make_lt(h2, min(h1, h3))
    k3 = make_lt(h3, h2)
    for i1 in range(-3,3+1):
        for i2 in range(-3,3+1):
            for i3 in range(-3,3+1):
                for l1 in [0, k1]:
                    for l2 in [0, k2]:
                        for l3 in [0, k3]:
                            ans = min(ans, check_count(l1 + i1, l2 + i2, l3 + i3))
    if ans == float('inf'):
        ans = -1
print(ans)
```
