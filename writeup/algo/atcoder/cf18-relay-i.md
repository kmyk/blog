---
layout: post
date: 2018-11-21T11:26:01+09:00
tags: [ "competitive", "writeup", "atcoder", "code-festival", "construction" ]
"target_url": [ "https://beta.atcoder.jp/contests/cf18-relay-open/tasks/relay2018_i" ]
---

# Code Festival (2018) Team Relay: I - 一円を笑う者は一円に泣く

## 解法

### 概要

すべて $$\bmod 5$$ で考え、適当に組み合わせて $$1, 2 \pmod{5}$$ を増やしたい。
$$3 + 4 \equiv 2$$ の変換を貪欲に行い、後は適当に合わせるのが最適。
$$O(1)$$。

不安なら $$3 + 4 \equiv 2$$ をする回数を総当たりしてもよい。

## 実装

``` python
#!/usr/bin/env python3
def solve(n, p):
    f = [ 0 ] * 5
    for p_i in p:
        f[p_i % 5] += 1

    def use(a, b):
        f[a] -= 1
        f[b] -= 1
        assert f[a] >= 0
        assert f[b] >= 0
        f[(a + b) % 5] += 1

    while f[3] and f[4]:
        use(3, 4)

    while f[3] >= 2:
        use(3, 3)

    while f[4] >= 3:
        use(4, 4)
        use(3, 4)

    if f[4] >= 2:
        use(4, 4)

    assert f[3] <= 1
    assert f[4] <= 1
    assert not f[3] or not f[4]

    if f[1] and f[3]:
        use(1, 3)

    if f[2] and f[3]:
        use(2, 3)

    if f[1] and f[4]:
        use(1, 4)

    if f[2] and f[4]:
        use(2, 4)

    while f[1] >= 2:
        use(1, 1)

    x = sum(p) - f[1] - 2 * f[2] + 2 * f[3] + f[4]
    y = max(1, f[1] + f[2])
    return (x, y)

if __name__ == '__main__':
    n = int(input())
    p = [ int(input()) for _ in range(n) ]
    print(*solve(n, p))
```
