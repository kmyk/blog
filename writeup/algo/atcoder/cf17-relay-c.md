---
layout: post
alias: "/blog/2017/11/27/cf17-relay-c/"
date: "2017-11-27T17:58:09+09:00"
tags: [ "competitive", "writeup", "atcoder", "codefestival", "team-relay", "binary-search" ]
"target_url": [ "https://beta.atcoder.jp/contests/cf17-relay-open/tasks/relay2_c" ]
---

# Code Festival Team Relay: C - Garden

## solution

二分探索するだけ。$O(N \log \mathrm{ans})$。

## implementation

``` c++
#include <cassert>
#include <climits>
#include <cstdio>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
using ll = long long;
using namespace std;

template <typename UnaryPredicate>
ll binsearch(ll l, ll r, UnaryPredicate p) { // [l, r), p is monotone
    assert (l < r);
    -- l;
    while (r - l > 1) {
        ll m = (l + r) / 2;
        (p(m) ? r : l) = m;
    }
    return r; // = min { x in [l, r) | p(x) }, or r
}

constexpr ll inf = LLONG_MAX / 3;
int main() {
    // input
    int n, k; scanf("%d%d", &n, &k);
    vector<ll> w(n);
    vector<int> d(n);
    repeat (i, n) {
        scanf("%lld%d", &w[i], &d[i]);
    }
    // solve
    ll result = binsearch(0, inf, [&](ll x) {
        ll cnt = 0;
        repeat (i, n) {
            if (w[i] <= x) {
                cnt += 1 + (x - w[i]) / d[i];
            }
        }
        return cnt >= k;
    });
    // output
    printf("%lld\n", result);
    return 0;
}
```
