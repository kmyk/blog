---
layout: post
alias: "/blog/2017/12/19/icpc-2017-asia-c/"
date: "2017-12-19T03:49:16+09:00"
tags: [ "competitive", "writeup", "icpc", "icpc-asia" ]
---

# AOJ 1380 / ACM-ICPC 2017 Asia Tsukuba Regional Contest: C. Medical Checkup

-   <http://judge.u-aizu.ac.jp/onlinejudge/description.jsp?id=1380>
-   <http://judge.u-aizu.ac.jp/onlinejudge/cdescription.jsp?cid=ICPCOOC2017&pid=C>

## problem

$n$人の人と可算個の機械$0, 1, 2, \dots$がある。
人々が機械を番号の順に使っていく。
人$i$は機械を使うのに時間$h\_i$かかり、どの機械も同時にひとりまでしか使えない。
時刻$t$でそれぞれの人がどの機械を使っている(あるいは使えるようになるのを待機している)か答えよ。

## solution

人を順番に見ていく。どの人$i$も機械$0$を時刻$a\_i$に使い始めて以降は$b\_i$の間隔で次の機械を使う。
よってこのふたつの値を更新しながら舐めればよい。
$O(n)$。

図:

```
0: 00000111112222233333444445555566666...
1:      000  111  222  333  444  555  ...
2:         000000011111112222222333333...
3:                00     11     22    ...
```

## implementation

``` c++
#include <bits/stdc++.h>
using ll = long long;
using namespace std;
template <class T> inline void chmax(T & a, T const & b) { a = max(a, b); }

int main() {
    int n, t; scanf("%d%d", &n, &t);
    ll offset = 0, interval = 0;
    while (n --) {
        int h; scanf("%d", &h);
        chmax<ll>(interval, h);
        ll p = (t - offset) / interval;
        ll q = (t - offset) % interval;
        int result = max<ll>(0, p + (q >= h));
        printf("%d\n", result + 1);
        offset += h;
    }
    return 0;
}
```
