---
layout: post
redirect_from:
  - /writeup/algo/codeforces/697-b/
  - /blog/2016/07/15/cf-697-b/
date: "2016-07-15T04:00:23+09:00"
tags: [ "competitive", "writeup", "codeforces" ]
"target_url": [ "http://codeforces.com/contest/697/problem/B" ]
---

# Codeforces Round #362 (Div. 2) B. Barnicle

hackが捗っていたようだが、ミスが怖いし面倒だし精々$200$点$300$点程度にしかならんしなあと思って静観した。

## problem

`${a}.${d}e${b}`の形の文字列が与えられる。`a` `d` `b`はそれぞれ整数である。
これを有理数として解釈し、(`e`を使わない形の、`12.34`のような)その$10$進数表記を出力せよ。

## solution

Please implement it precisely.

You should take care for some cases like `0.0e0`, `1.0e0` or `0.01e1`.
You can check your implementation for the corner cases using formatter of your language, like:

``` python
#!/usr/bin/env python3
s = input()
s = str(float(s))
if s.endswith('.0'):
    s = s[:-2]
print(s)
```

## implementation

``` python
#!/usr/bin/env python3
s = input()
a, s = s.split('.')
d, b = s.split('e')
for i in range(int(b)):
    d += '0'
    a += d[0]
    d = d[1:]
s = a + '.' + d
while s[0] == '0':
    s = s[1:]
while s[-1] == '0':
    s = s[:-1]
if s[-1] == '.':
    s = s[:-1]
if s == '' or s[0] == '.':
    s = '0' + s
print(s)
```
