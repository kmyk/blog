---
layout: post
alias: "/blog/2017/07/02/icpc-2017-domestic-practice-b/"
date: "2017-07-02T22:40:49+09:00"
title: "ACM-ICPC 2017 模擬国内予選: B. 海岸線"
tags: [ "competitive", "writeup", "aoj", "icpc-domestic" ]
---

## solution

そのままやる。$O(T)$。

注意としては、波は時刻$1$から時刻$T$までの$T$点分与えられるが時間は$[1, 2)$から$[T-1, T)$までの$T-1$区間であること。つまり値$x\_T$は完全に無視される。

## implementation

``` c++
#include <cstdio>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))

int main() {
    while (true) {
        int t, d, l; scanf("%d%d%d", &t, &d, &l);
        if (t == 0) break;
        int result = 0;
        int wetness = 0;
        repeat (i, t) {
            int x; scanf("%d", &x);
            if (l <= x) {
                wetness = d;
            }
            if (i + 1 < t) {
                if (wetness) {
                    ++ result;
                    -- wetness;
                }
            }
        }
        printf("%d\n", result);
    }
    return 0;
}
```
