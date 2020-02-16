---
layout: post
redirect_from:
  - /writeup/algo/atcoder/abc-032-c/
  - /blog/2016/02/22/abc-032-c/
date: 2016-02-22T21:58:10+09:00
tags: [ "competitive", "writeup", "atcoder", "abc", "shakutori-hou", "typical-problem" ]
---

# AtCoder Beginner Contest 032 C - 列

典型的なしゃくとり法。
この手の教科書に載ってるアルゴリズムそのままな問題[^1]は練習会でまだ不慣れな人に投げつけるのに良いので[tag](http://kimiyuki.net/blog/categories/typical-problem)付けて集めておきたい。

## [C - 列](https://beta.atcoder.jp/contests/abc032/tasks/abc032_c)

``` python
#!/usr/bin/env python3
n, k = map(int,input().split())
s = [int(input()) for _ in range(n)]
if 0 in s:
    ans = n
else:
    ans = 0
    acc = 1 # procuct of s_i in [l,r]
    l = 0
    for r in range(n): # [l,r]
        acc *= s[r]
        if k < acc:
            acc /= s[l]
            l += 1
        ans = max(ans, r - l + 1)
print(ans)
```

---

# AtCoder Beginner Contest 032 C - 列

[^1]: 典型問題/教育的問題/良問 あたりの単語の一般的な用法を理解してないので通用する呼び方がいまいち分からない。とりあえず`典型`を使っておく。
