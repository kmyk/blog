---
layout: post
alias: "/blog/2016/12/04/code-festival-2016-asapro-2-a/"
date: "2016-12-04T02:32:02+09:00"
tags: [ "competitive", "writeup", "atcoder", "codefestival", "expected-value" ]
"target_url": [ "https://beta.atcoder.jp/contests/cf16-tournament-round2-open/tasks/asaporo_e" ]
---

# CODE FESTIVAL 2016 Elimination Tournament Round 2: A - 迷子の高橋君 / Takahashi is Missing!

実績解除: editorialを撃墜

## solution

漸化式を立てて解いて$O(1)$。

青木君が座標$0$、高橋君が座標$x$にいる状態からの期待値を$f(x)$とする。

自明に$f(0) = 0$である。
$0.01 \le p \le 1$であるようにしておいて、高橋君とすれ違う危険がない場合は近付くべきなので$f(x+2) = 1 + pf(x) + (1-p)f(x+2)$となる。
整理すると$f(x+2) = \frac{1}{p} + f(x)$である。偶数のときはこのまま$f(2x) = \underbrace{\frac{1}{p} + \frac{1}{p} + \dots + \frac{1}{p}}\_{x \; \text{times}} + f(0) = \frac{x}{p}$。
$f(1)$のときは少し面倒であるが、すれ違ってしまうと必ずしも捕まえられなくなるので動くべきではなく、$f(1) = 1 + (1-p)f(2) = 1 + \frac{1-p}{p} = \frac{1}{p}$となる。
あるいは$x$が奇数の時は初手で$1$ターン足踏みして偶奇を揃えると考えてもよい。
両方を合わせると$f(x) = \lceil \frac{x}{2} \rceil \cdot \frac{1}{p}$となる。

## implementation

``` python
#!/usr/bin/env python3
import math
x = int(input())
p = int(input())/100
print(math.ceil(x / 2) / p)
```
