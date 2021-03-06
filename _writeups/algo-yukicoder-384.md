---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/384/
  - /blog/2016/07/02/yuki-384/
date: 2016-07-02T00:23:15+09:00
tags: [ "competitive", "writeup", "yukicoder", "game" ]
"target_url": [ "http://yukicoder.me/problems/no/384" ]
---

# Yukicoder No.384 マス埋めゲーム2

## solution

$O(1)$。

>   最後のマスを埋めてしまった人の負けになる。

なので解ける。

行/列の選択について、それぞれ必ず端から使っていくものとしてよく、$H$個目の行/$W$個目の列を使用したときちょうどそのときに負けると言える。
ある行/列を使用したとき、それ以外の行/列が使えなくなることはない。
よって$H + W - 1$番目に動く人が負け。
剰余を取れば答えがでる。
ただし$H = 1$や$W = 1$の場合がコーナーケース。

図。指定できない行/列を`x`で示した。

``` plain
\ oooooox

o .......
o .......
o .......
o .......
o .......
x .......
```

## implementation

``` python
#!/usr/bin/env python3
h, w, n, k = map(int,input().split())
if h == 1:
    g = w
elif w == 1:
    g = h
else:
    g = h + w - 1
print(['NO', 'YES'][(g-1) % n == k-1])
```
