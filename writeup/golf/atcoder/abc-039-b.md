---
layout: post
alias: "/blog/2016/06/11/abc-039-b/"
date: 2016-06-11T23:00:02+09:00
tags: [ "competitive", "writeup", "atcoder", "abc", "awk", "golf", "perl" ]
"target_url": [ "https://beta.atcoder.jp/contests/abc039/tasks/abc039_b" ]
---

# AtCoder Beginner Contest 039 B - エージェント高橋君

## implementation

### awk 17byte

``` awk
$0=sqrt(sqrt($1))
```

`$0=$1**0.25`が通ればよかったのだが、atcoderは`gawk`でなく`mawk`なのでだめ

また、hanada3355さんによる7byteの提出が存在する: <https://beta.atcoder.jp/contests/abc039/submissions/761518>

### perl 13byte

``` perl
print<>**0.25
```
