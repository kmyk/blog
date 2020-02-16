---
layout: post
redirect_from:
  - /blog/2015/11/20/code-festival-2015-morning-a/
date: 2015-11-20T00:06:20+09:00
tags: [ "competitive", "writeup", "codefestival", "atcoder" ]
---

# CODE FESTIVAL 2015 朝プロ A - ヘイホー君と加算

EasyのA。本番中は触れていない。

<!-- more -->

## [A - ヘイホー君と加算](https://beta.atcoder.jp/contests/code-festival-2015-morning-easy/tasks/cf_2015_morning_easy_a) {#a}

### 問題

$N$以上の平方数で最小のものと、$N$との差を答えよ。

### 解法

制約が軽いので愚直に書けばよい。

### 実装

``` python
#!/usr/bin/env python3
import math
n = int(input())
i = 0
while int(math.sqrt(n+i))**2 != n+i:
    i += 1
print(i)
```
