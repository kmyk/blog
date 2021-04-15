---
layout: post
redirect_from:
  - /writeup/algo/etc/fhc-2016-round1-c/
  - /blog/2016/01/18/fhc-2016-round1-c/
date: 2016-01-18T01:17:45+09:00
tags: [ "competitive", "writeup", "facebook-hacker-cup", "expected-value" ]
---

# Facebook Hacker Cup 2016 Round 1 Yachtzee

ドルは実数。

## [Yachtzee](https://www.facebook.com/hackercup/problem/512731402225321/)

### 解法

区間で切ってそれぞれ期待値を計算するだけ。

$\Sigma C_i$を1区間として、$A$を含む区間、$B$を含む区間、その間の区間をそれぞれ計算し、重みを付けて足し合わせる。
$A$を含む区間は引く感じにすると少し楽。

### 実装

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <cstdio>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;
double bar(ll b, vector<ll> const & c, double l) {
    int n = c.size();
    assert (b <= accumulate(c.begin(), c.end(), 0ll));
    double e = 0;
    ll acc = 0;
    repeat (j,n) {
        ll t = min(c[j], b - acc);
        e += 0.5*t * (t / l);
        acc += t;
        if (acc == b) break;
    }
    return e;
}
double foo() {
    ll n, a, b; cin >> n >> a >> b;
    vector<ll> c(n); repeat (i,n) cin >> c[i];
    ll sum_c = accumulate(c.begin(), c.end(), 0ll);
    ll l = b - a;
    ll d = b / sum_c - a / sum_c;
    return bar(sum_c,c,l) * d + bar(b % sum_c,c,l) - bar(a % sum_c,c,l);
}
int main() {
    int testcases; cin >> testcases;
    repeat (testcase, testcases) {
        printf("Case #%d: %.12lf\n", testcase+1, foo());
    }
    return 0;
}
```
