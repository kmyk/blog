---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/81/
  - /blog/2016/12/27/yuki-81/
date: "2016-12-27T16:13:14+09:00"
tags: [ "competitive", "writeup", "yukicoder" ]
"target_url": [ "http://yukicoder.me/problems/no/81" ]
---

# Yukicoder No.81 すべて足すだけの簡単なお仕事です。

%20さんが大量撃墜してた。
これに関する彼のblog記事は面白かったので読むとよい: [yukicoder No.81 すべて足すだけの簡単なお仕事です。 - 37.50.48](http://i-i.hatenablog.jp/entry/2016/12/29/021501)。

## solution

(言語縛りでなければ)多倍長演算ができる言語を使えばよい。

あるいは`__float128`(仮数部$10$進$33$桁ぐらい)を使ってもよさそう。
`__float80`(仮数部$64$bit)だとちょっと足りない。

## implementation

`int`や`fractions`でもよいが、`decimal`が直接的で楽だった。

``` python
#!/usr/bin/env python3
import decimal
n = int(input())
a = [ decimal.Decimal(input()) for _ in range(n) ]
# print('%.10f' % sum(a)) # WA
print('{:.10f}'.format(sum(a)))
```
