---
layout: post
alias: "/blog/2015/11/20/code-festival-2015-morning-c/"
date: 2015-11-20T00:06:41+09:00
tags: [ "competitive", "writeup", "codefestival", "atcoder" ]
---

# CODE FESTIVAL 2015 朝プロ C - ヘイホー君と最終試験

素早く通せた。でも2WA。

赤点取ったら木の下に埋められそうだなとか思った。

<!-- more -->

## [C - ヘイホー君と最終試験](https://beta.atcoder.jp/contests/code-festival-2015-morning-easy/tasks/cf_2015_morning_easy_c) {#c}

### 問題

$M$点満点の試験を$N$回行い、上位$K$回の試験の平均点が$R$以上であれば単位が認定される。
$N-1$回の試験の結果が分かっている。単位認定のためには最後の試験で何点以上とればよいか。

### 解法

素直に書けばよい。

### 実装

``` python
#!/usr/bin/env python3
n, k, m, r = map(int,input().split())
s = []
for i in range(n-1):
    s.append(int(input()))
s.sort(reverse=True)
if sum(s[:k]) >= k * r:
    print(0)
else:
    t = k*r - sum(s[:k-1])
    if m < t:
        print(-1)
    else:
        print(t)
```
