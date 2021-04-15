---
layout: post
redirect_from:
  - /writeup/algo/csacademy/72-a/
  - /writeup/algo/cs-academy/72-a/
  - /blog/2018/03/08/csa-72-a/
date: "2018-03-08T12:04:29+09:00"
tags: [ "competitive", "writeup", "csa", "golf", "perl" ]
"target_url": [ "https://csacademy.com/contest/round-72/task/reversed-number/" ]
---

# CS Academy Round #72. Reversed Number

## implementation

perl $22$byte

``` perl
print`tee x`<`rev<x`|0
```

perlやawkで文字列をreverseするのは難しいらしい。
rubyにはあるけど整数との変換が遅い。
なのでほとんどbash。しかし`expr`するよりperlから呼んだ方が速かった。
