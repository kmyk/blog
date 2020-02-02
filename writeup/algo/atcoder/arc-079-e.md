---
layout: post
alias: "/blog/2017/07/29/arc-079-e/"
date: "2017-07-29T23:07:11+09:00"
title: "AtCoder Regular Contest 079: E - Decrease (Judge ver.)"
tags: [ "competitive", "writeup", "atcoder", "arc" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc079/tasks/arc079_c" ]
---

## solution

操作は数列のうち最も大きい要素以外に対しても好きな順番で行なってよい。
つまり$a\_i = nk + r$として$a\_i \gets r, \; a\_j \gets a\_j - k \; (\text{for all} j \ne i)$を繰り返しても同じ結果が得られる。

証明はやればできるのでは (知らず)。
計算量もよく分からず。まあ対数オーダーでできそうな感じがありますね。

## implementation

``` c++
#include <algorithm>
#include <cstdio>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define whole(f, x, ...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using ll = long long;
using namespace std;

int main() {
    int n; scanf("%d", &n);
    vector<ll> a(n); repeat (i, n) scanf("%lld", &a[i]);
    ll result = 0;
    while (true) {
        whole(sort, a);
        if (a[n - 1] < n) break;
        ll k = a[n - 1] / n;
        a[n - 1] %= n;
        repeat (i, n - 1) a[i] += k;
        result += k;
    }
    printf("%lld\n", result);
    return 0;
}
```
