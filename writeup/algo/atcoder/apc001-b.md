---
layout: post
title: "AtCoder Petrozavodsk Contest 001: B - Two Arrays"
date: 2018-07-09T20:26:48+09:00
tags: [ "competitive", "writeup", "atcoder", "apc" ]
"target_url": [ "https://beta.atcoder.jp/contests/apc001/tasks/apc001_b" ]
---

## solution

操作を帰着/分割し(典型)上手くやる。$O(N)$。

実質的に操作C「$a_i$に$1$を足す」が可能なため、$a_i \lt b_i$の場合は自明にこれを解消できる。
一方$b_i \lt a_i$の場合が困難である。
そこで操作を操作A「$a_i$に$2$を足す」と操作B「$b_i$に$1$を足す」に分解し、さきに操作Bだけ終わらせてしまい、その回数以上の操作Aを行えるかどうか判定すればよい。残りは操作Cとして処理できるため。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
using ll = long long;
using namespace std;

int main() {
    // input
    int n; cin >> n;
    vector<ll> a(n);
    REP (i, n) cin >> a[i];
    vector<ll> b(n);
    REP (i, n) cin >> b[i];

    // solve
    ll cnt = 0;
    REP (i, n) {
        if (a[i] > b[i]) {
            ll k = a[i] - b[i];
            b[i] += k;
            cnt += k;
        }
    }
    REP (i, n) {
        if (a[i] < b[i]) {
            ll k = (b[i] - a[i]) / 2;
            a[i] += 2 * k;
            cnt -= k;
            if (a[i] < b[i]) {
                a[i] += 2;
                b[i] += 1;
            }
        }
    }
    bool answer = (cnt <= 0);

    // output
    cout << (answer ? "Yes" : "No") << endl;
    return 0;
}
```
