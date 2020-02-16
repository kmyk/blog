---
layout: post
alias: "/blog/2018/02/22/agc-020-b/"
date: "2018-02-22T22:20:44+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc020/tasks/agc020_b" ]
---

# AtCoder Grand Contest 020: B - Ice Rink Game

## solution

逆から考える。
その時点で残っている人数としてあり得る値$x$の集合$X$を、$X = \\{ 2 \\}$から始めて復元していく。
このときこの集合$X$は区間$[l, r)$となることが確認できる。
$O(N)$。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define ALL(x) begin(x), end(x)
using ll = long long;
using namespace std;

int main() {
    // input
    int k; scanf("%d", &k);
    vector<int> a(k); REP (i, k) scanf("%d", &a[i]);
    // solve
    reverse(ALL(a));
    ll l = 2, r = 3;
    for (int a_i : a) {
        l = (l + a_i - 1) / a_i * a_i;
        r = (r + a_i - 1) / a_i * a_i;
    }
    // output
    if (l == r) {
        printf("-1\n");
    } else {
        printf("%lld %lld\n", l, r - 1);
    }
    return 0;
}
```
