---
layout: post
alias: "/blog/2017/07/09/agc-017-a/"
date: "2017-07-09T23:44:34+09:00"
title: "AtCoder Grand Contest 017: A - Biscuits"
tags: [ "competitive", "writeup", "atcoder", "agc" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc017/tasks/agc017_a" ]
---

## solution

普通に数える。$O(N^3)$。

数列$A$中の偶数な項の数を$E$、奇数な項の数を$O$とする。
偶数を足しても偶奇は保たれるので偶数な項の使用は自由で、$2^E$通り。
奇数な項はちょうど$P \pmod{2}$個使わなければならないので、$\sum\_{0 \le r \le O \land r \equiv P \pmod{2}} {}\_OC\_r$通り。
この積が答え。

## implementation

``` c++
#include <algorithm>
#include <cstdio>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define whole(f, x, ...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using ll = long long;
using namespace std;

ll choose(int n, int r) { // O(r) for small n
    ll acc = 1;
    repeat (i,r) acc = acc * (n-i) / (i+1);
    return acc;
}
int main() {
    int n, p; scanf("%d%d", &n, &p);
    vector<int> a(n); repeat (i, n) scanf("%d", &a[i]);
    int even = whole(count_if, a, [](int a_i) { return a_i % 2 == 0; });
    int odd = n - even;
    ll result = 0;
    for (int k = p; k <= odd; k += 2) {
        result += choose(odd, k);
    }
    result *= 1ll << even;
    printf("%lld\n", result);
    return 0;
}
```
