---
layout: post
alias: "/blog/2018/02/22/agc-020-c/"
date: "2018-02-22T22:20:50+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc", "dp", "bitset" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc020/tasks/agc020_c" ]
---

# AtCoder Grand Contest 020: C - Median Sum

## solution

$X \subseteq 2^N$と$X^C$の対応を考えれば、目的の中央値は$\frac{\sum A\_i}{2}$以上の最小のものである。部分和問題になるのでbitset。$O(\sum A\_i)$。

後輩曰く、$X \subseteq 2^N$と$X^C$の対応は差分を取ると見える。階差数列が左右対称になる。
$2000^3$はbitsetなしでもぎりぎりなんとかなるので想定がbitsetは妥当なはず。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define ALL(x) begin(x), end(x)
using namespace std;

int main() {
    // input
    int n; scanf("%d", &n);
    vector<int> a(n); REP (i, n) scanf("%d", &a[i]);

    // solve
    int sum_a = accumulate(ALL(a), 0);
    bitset<2000 * 2000 + 1> dp = {};
    dp[0] = 1;
    for (int a_i : a) {
        dp |= dp << a_i;
    }
    int j = (sum_a + 1) / 2;
    while (not dp[j]) ++ j;

    // output
    printf("%d\n", j);
    return 0;
}
```
