---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/365/
  - /blog/2016/04/30/yuki-365/
date: 2016-04-30T00:41:26+09:00
tags: [ "competitive", "writeup", "yukicoder" ]
"target_url": [ "http://yukicoder.me/problems/1081" ]
---

# Yukicoder No.365 ジェンガソート

星1だったが途中で星2へ昇格した。

brainfuckできるかな？と思っていたがだめそうだったのでpythonに逃げたが、逃げた先でもWAをだしてしまった。

## solution

要素ごとにそれを動かさなければいけないかどうかを考える。$O(N)$。

それより手前にそれより大きい要素のある要素は動かす必要がある。
他の動かした要素より小さい要素は動かす必要がある。
これ以外は動かす必要はない。

動かす順番を適当にすれば、各々ちょうど$1$回動かせばすむ。

## implementation

``` python
#!/usr/bin/env python3
n = int(input())
xs = list(map(int,input().split()))
y = 0
z = 0
for x in xs:
    if y < x:
        y = x
    else:
        z = max(z, x)
ans = 0
for x in xs:
    if x <= z:
        ans += 1
print(ans)
```
