---
layout: post
redirect_from:
  - /blog/2015/11/20/code-festival-2015-morning-b/
date: 2015-11-20T00:06:37+09:00
tags: [ "competitive", "writeup", "codefestival", "atcoder" ]
---

# CODE FESTIVAL 2015 朝プロ B - ヘイホー君と置き換え

>   ある文字列を 2 回繰り返してできる文字列を、平方と呼びます。

っていうのなんだか気持ち悪いなって思った。

<!-- more -->

## [B - ヘイホー君と置き換え](https://beta.atcoder.jp/contests/code-festival-2015-morning-easy/tasks/cf_2015_morning_easy_b) {#b}

### 問題

長さ$N$の文字列$S$が与えられる。文字列$S$中の文字をひとつ選んで別の文字で置き換えるという操作を行うことができる。
この$S$から、なんらかの文字列$T$の2回の繰り返しで表現されるような文字列$T \oplus T$を作りたい。必要な最小の操作の回数を答えよ。不可能なら$-1$を答えよ。

### 解法

$N$が奇数なら不可能。
偶数なら可能。
文字列$S$の前半分の文字についてだけ、変更するかしないか見ればよい。

### 実装

``` python
#!/usr/bin/env python3
n = int(input())
s = input()
if n % 2 == 1:
    i = -1
else:
    i = 0
    for j in range(n//2):
        if s[j] != s[n//2+j]:
            i += 1
print(i)
```
