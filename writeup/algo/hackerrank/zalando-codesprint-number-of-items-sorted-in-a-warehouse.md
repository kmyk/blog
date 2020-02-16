---
layout: post
redirect_from:
  - /blog/2016/06/05/hackerrank-zalando-codesprint-number-of-items-sorted-in-a-warehouse/
date: 2016-06-05T19:18:05+09:00
tags: [ "competitive", "writeup", "hackerrank", "binary-search" ]
"target_url": [ "https://www.hackerrank.com/contests/zalando-codesprint/challenges/number-of-items-sorted-in-a-warehouse" ]
---

# HackerRank Zalando CodeSprint: Processing Time Inside a Warehouse

## problem

$M$人の作業員で$N$個の荷物をトラックに載せる。
$i$番目の作業員は、荷物$1$個を$P_i$分で処理できる。
全て処理し終えるのに最短で何分かかるか。

## solution

Do binary search. $O(N \log M)$.

Find the $\min \\{ t \mid \phi(t) \\}$, where $\phi(t)$ is the predicate that the process can be done in $t$ minutes.

## implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;
int main() {
    int n, m; cin >> n >> m;
    vector<int> ps(m); repeat (i,m) cin >> ps[i];
    ll l = 0;
    ll r = n *(ll) *min_element(ps.begin(), ps.end()); // (l, r]
    while (l + 1 < r) {
        ll t = (l + r) / 2;
        ll rem = n;
        for (int p : ps) {
            rem -= t / p;
            if (rem <= 0) break;
        }
        (rem <= 0 ? r : l) = t;
    }
    cout << r << endl;
    return 0;
}
```
