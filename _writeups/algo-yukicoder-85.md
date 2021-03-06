---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/85/
  - /blog/2017/01/08/yuki-85/
date: "2017-01-08T21:54:54+09:00"
tags: [ "competitive", "writeup", "yukicoder" ]
"target_url": [ "http://yukicoder.me/problems/no/85" ]
---

# Yukicoder No.85 TVザッピング(1)

ハミルトン閉路問題だけどグラフの形が綺麗だから自明、って思ったらコーナーケースに$2$回も刺された。

## solution

奇数$\times$奇数がだめ。$O(1)$。

閉路を見るので$C$は不要。
$1 \times 2$と$2 \times 1$は自明な閉路なので`YES`。
それ以外の場合、奇数$\times$奇数がだめ。これはまず$2 \times 2$の閉路を作り、それへ$2 \times 1$を付け足して伸ばしていくことを考えるとなんとなく分かる。

## implementation

``` python
#!/usr/bin/env python3
h, w, _ = map(int, input().split())
if h == 1 or w == 1:
    ans = h == 2 or w == 2
else:
    ans = h % 2 == 0 or w % 2 == 0
print(['NO', 'YES'][ans])
```
