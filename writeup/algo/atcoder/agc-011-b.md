---
layout: post
alias: "/blog/2017/03/12/agc-011-b/"
date: "2017-03-12T22:48:18+09:00"
title: "AtCoder Grand Contest 011: B - Colorful Creatures"
tags: [ "competitive", "writeup", "atcoder", "agc", "shakutori-method", "greedy" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc011/tasks/agc011_b" ]
---

## solution

sortしてしゃくとりっぽい貪欲。$O(N)$。

生き物$l$が食べられる最大の大きさの生き物$r$をそれぞれについて求めればよい。
これは$A\_{l_1} \le A\_{l_2}$ならば$A\_{r_1} \le A\_{r_2}$なので、数列$A$をsortして$l$を増やしながら$r$も増やしていくことで効率よく求まる。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using ll = long long;
using namespace std;
int main() {
    int n; cin >> n;
    vector<int> a(n); repeat (i,n) cin >> a[i];
    whole(sort, a);
    ll acc = 0;
    int l = 0, r = 0;
    while (true) {
        if (r == l) {
            acc += a[l];
            ++ r;
        }
        while (r < n and a[r] <= 2*acc) {
            acc += a[r];
            ++ r;
        }
        if (r == n) break;
        ++ l;
    }
    cout << r - l << endl;
    return 0;
}
```
