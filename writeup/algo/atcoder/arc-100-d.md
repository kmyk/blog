---
layout: post
date: 2018-07-01T23:12+09:00
tags: [ "atcoder", "arc", "competitive", "writeup", "cumulative-sum", "binary-search" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc100/tasks/arc100_b" ]
---

# AtCoder Regular Contest 100: D - Equal Cut

<!-- {% raw %} -->

## solution

中央の区切りを全探索、左右の区切りはちょうど半分ぐらいのところを適当にする。 しゃくとり法なら$O(N)$にできるが二分探索で$O(N \log N)$でもよい。

全探索は$O(N^3)$で無理だが、こういうので1点固定するのは典型で、固定するとしたら中央。後は雰囲気でやる。

本番は未証明のまま出したけどゆっくり考えると自明だった。
次を示せばよい:

-   $f(\vec{x}) = \mathrm{max}(\vec{x}) - \mathrm{min}(\vec{x})$とし、$B, C, D, E \in \mathbb{Z}$で$B \le C$とする。このとき$f(B, C, D, E) \le f(B - 1, C + 1, D, E)$である。


## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < int(n); ++ (i))
#define ALL(x) begin(x), end(x)
using ll = long long;
using namespace std;
template <class T> inline void chmin(T & a, T const & b) { a = min(a, b); }

template <typename UnaryPredicate>
int64_t binsearch(int64_t l, int64_t r, UnaryPredicate p) {
    assert (l <= r);
    -- l;
    while (r - l > 1) {
        int64_t m = l + (r - l) / 2;  // to avoid overflow
        (p(m) ? r : l) = m;
    }
    return r;
}

int main() {
    // input
    int n; cin >> n;
    vector<ll> a(n);
    REP (i, n) cin >> a[i];

    // solve
    vector<ll> acc(n + 1);
    partial_sum(ALL(a), acc.begin() + 1);
    ll answer = LLONG_MAX;
    REP (m, n + 1) {
        int l0 = binsearch(0, m + 1, [&](int l) {
            ll b = acc[l] - acc[0];
            ll c = acc[m] - acc[l];
            return b >= c;
        });
        int r0 = binsearch(m, n + 1, [&](int r) {
            ll d = acc[r] - acc[m];
            ll e = acc[n] - acc[r];
            return d >= e;
        });
        REP3 (l, max(0, l0 - 3), min(m, l0 + 3) + 1) {
            REP3 (r, max(m, r0 - 3), min(n, r0 + 3) + 1) {
                ll b = acc[l] - acc[0];
                ll c = acc[m] - acc[l];
                ll d = acc[r] - acc[m];
                ll e = acc[n] - acc[r];
                array<ll, 4> bcde = {{ b, c, d, e }};
                chmin(answer, *max_element(ALL(bcde)) - *min_element(ALL(bcde)));
            }
        }
    }

    // output
    cout << answer << endl;
    return 0;
}
```

<!-- {% endraw %} -->
