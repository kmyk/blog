---
layout: post
redirect_from:
  - /writeup/algo/atcoder/cf17-final-b/
  - /blog/2017/11/26/cf17-final-b/
date: "2017-11-26T10:02:21+09:00"
tags: [ "competitive", "writeup", "atcoder", "codefestival" ]
"target_url": [ "https://beta.atcoder.jp/contests/cf17-final-open/tasks/cf17_final_b" ]
---

# CODE FESTIVAL 2017 Final: B - Palindrome-phobia

文字種が$4$になるとどうなるのだろう (考えてない)

## solution

文字の数を数えた後は$O(1)$。

始めに文字`a`を使うすると、その後ろには`a`は置けない。さらに`b`を置いて`ab`とすると、この後ろには`c`以外を置くことはできない。`abc`となれば同様に必ず`a`を置かなければならない。これを繰り返せば、目標の文字列が構成されるなら`abcabc...abcab`とならねばならない。
よって、入力はそれぞれの文字の数$a, b, c \in \mathbb{N}$が与えられるとしてよく、$\max \\{ a, b, c \\} \le \min \\{ a, b, c \\} + 1$が答え。

## implementation

``` python
#!/usr/bin/env python3
s = input()
a = s.count('a')
b = s.count('b')
c = s.count('c')
result = (max(a, b, c) <= min(a, b, c) + 1)
print(['NO', 'YES'][result])
```
