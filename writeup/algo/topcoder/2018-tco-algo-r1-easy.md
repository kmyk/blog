---
layout: post
alias: "/blog/2018/04/22/2018-tco-algo-r1-easy/"
date: "2018-04-22T02:57:49+09:00"
tags: [ "competitive", "writeup", "topcoder", "srm", "tco", "binary-search" ]
---

# 2018 TCO Algorithm: Easy. RedDragonInn

## solution

答えを二分探索。上限は大きめに取っておくとよい。$O(NX)$。

## note

-   TopCoderのわりに問題文がつらい。 `Red Dragon Inn` って言われると `Inn` って名前の赤い龍なのかなと思いませんか。思わないですね。英語力がないだけだねこれは。
-   部屋でにぶたんしてる人 他に誰もいなかった。みんな頭良すぎる

## implementation

``` c++
#include <bits/stdc++.h>
using namespace std;
class RedDragonInn { public: int maxGold(int N, int X); };

template <typename UnaryPredicate>
int64_t binsearch_max(int64_t l, int64_t r, UnaryPredicate p) {
    assert (l <= r);
    ++ r;
    while (r - l > 1) {
        int64_t m = l + (r - l) / 2;  // avoid overflow
        (p(m) ? l : r) = m;
    }
    return l;
}

int RedDragonInn::maxGold(int N, int X) {
    return binsearch_max(0, 1e9 + 7, [&](int C) {
        return (C / 2) / N <= X;
    });
}
```
