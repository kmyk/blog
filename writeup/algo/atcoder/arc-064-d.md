---
layout: post
alias: "/blog/2016/12/05/arc-064-d/"
date: "2016-12-05T15:43:07+09:00"
tags: [ "competitive", "writeup", "atcoder", "game" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc064/tasks/arc064_b" ]
---

# AtCoder Regular Contest 064: D - An Ordinary Game

しばらく考えて分からなかったのですぐに解法を見てしまった。

## solution

最終結果の偶奇。$O(1)$。

文字列$s$から始めて最終的にどのような文字列で終わるかを考える。
文字がどれも消せないのは(元々消せない両端に依存して)`abababa`あるいは`abababab`のような形。
消す順番で間に挟む文字や長さは変化しうるが、両端の文字が一致していれば奇数長、そうでなければ偶数長というのは変わらない。
毎ターン長さが$1$ずつ縮むので、始めの長さの偶奇と合わせて勝者は定まる。

つまり誰がどう戦っても勝者は$s$によって同じ。

## implementation

``` python
#!/usr/bin/env python3
s = input()
g = (s[0] == s[-1]) ^ (len(s) % 2 != 0)
print(['Second', 'First'][g])
```
