---
redirect_from:
  - /writeup/algo/atcoder/soundhound2018-summer-qual-c/
layout: post
date: 2018-07-07T23:53:03+09:00
tags: [ "competitive", "writeup", "atcoder", "golf", "awk" ]
"target_url": [ "https://beta.atcoder.jp/contests/soundhound2018-summer-qual/tasks/soundhound2018_summer_qual_c" ]
---

# SoundHound Inc. Programming Contest 2018 -Masters Tournament-: C - Ordinary Beauty

## solution

平均なので総和と分母を考える(典型)。$O(1)$。

$n^m$ 通りの数列すべての美しさの総和を考えよう。
隣接する$2$項は$m - 1$箇所あり、差が$d$な組はそれぞれの箇所で$k = k(n, d) \in \\{ 0, \; 2(n - d), \; d \\}$通りほどあり、残りの$m - 2$項は任意。
よって美しさの総和は$(m - 1) \cdot k \cdot n^{m - 2}$。
これが分子となるので、答えは$\frac{k(m - 1)}{n^2}$。

(なお本番はgolfモードだったのでサンプルからguessingで通しました)

## implementation

awk $50$byte 暫定最短だがそのうち抜かれそう。

``` awk
{printf"%.9f",($3?2*sqrt(($1-$3)^2):$1)*--$2/$1^2}
```

基本解はこれ。

``` python
#!/usr/bin/env python3
n, m, d = map(int, input().split())
k = (max(0, n - d) * 2 if d else n)
print(k * (m - 1) / n ** 2)
```

注意点:

-   出力精度不足のため `printf` が必要 (awkの利点 `$0` が死ぬ)
-   absは `(x<0?-x:x)` より `sqrt(x^2)` の方が短い (初めて知った)
