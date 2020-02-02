---
layout: post
alias: "/blog/2017/07/14/icpc-2017-domestic-a/"
date: "2017-07-14T23:50:33+09:00"
title: "ACM-ICPC 2017 国内予選: A. 太郎君の買物"
tags: [ "competitive", "writeup", "icpc", "icpc-domestic" ]
---

終了後に解いて書いた。

## solution

全部の対を試す。$O(N^2)$。

## implementation

``` c++
#include <cstdio>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
using namespace std;
template <class T> inline void setmax(T & a, T const & b) { a = max(a, b); }

int main() {
    while (true) {
        int n, m; scanf("%d%d", &n, &m);
        if (n == 0 and m == 0) break;
        vector<int> a(n); repeat (i, n) scanf("%d", &a[i]);
        int result = 0;
        repeat (j, n) repeat (i, j) {
            if (a[i] + a[j] <= m) {
                setmax(result, a[i] + a[j]);
            }
        }
        if (result) {
            printf("%d\n", result);
        } else {
            printf("NONE\n");
        }
    }
    return 0;
}
```
