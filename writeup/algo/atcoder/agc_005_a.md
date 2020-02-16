---
layout: post
redirect_from:
  - /writeup/algo/atcoder/agc-005-a/
  - /blog/2017/09/02/agc-005-a/
date: "2017-09-02T08:22:06+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc005/tasks/agc005_a" ]
---

# AtCoder Grand Contest 005: A - STring

$i$回目には$a\_i$番目の`ST`を取り除く、のようにすると$O(\|X\|^2)$になりそう。

## solution

貪欲な感じで。$O(\|X\|)$。

最も左側のものを取り除くことを繰り返すので、空文字列から始めて末尾に$X$から$1$文字ずつ付け加えていき消せるか見ればよい。
操作対象は長さ$2$の連続な部分文字列のみなので、見る範囲は追加した部分のみでよい。
$O(\|X\|)$回の操作ごとに$O(1)$なので全体で$O(\|X\|)$。

## implementation

``` python
#!/usr/bin/env python3
x = input()
s = 0
t = 0
for c in x:
    if c == 'S':
        s += 1
    elif c == 'T':
        if s:
            s -= 1
        else:
            t += 1
    else:
        assert False
print(s + t)
```
