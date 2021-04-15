---
redirect_from:
  - /writeup/algo/atcoder/tenka1-2016-qualb-e/
layout: post
date: 2018-07-07T07:40:13+09:00
tags: [ "competitive", "writeup", "atcoder", "tenka1", "dp", "segment-tree" ]
"target_url": [ "https://beta.atcoder.jp/contests/tenka1-2016-qualb/tasks/tenka1_2016_qualB_e" ]
---

# 天下一プログラマーコンテスト2016予選B: E - 天下一合体

## 解法

まず愚直DPを考えると、$i$番目まで見て$j$要素に分割したときの最小値
<div>$$\mathrm{dp}(r, j + 1) = \min \left\{ \mathrm{dp}(l, j) + \left|\sum_{l \le i \lt r}a_i\right| \mid l \lt r \right\}$$</div> である。
とりあえず累積和$A_i$を取って左端は定数(典型)として処理したいが、絶対値関数が邪魔をして
<div>$$\mathrm{dp}(r, j + 1) = \min \left( \min \left\{ \mathrm{dp}(l, j) - A_l \mid l \lt r \land A_l \le A_r \right\} + A_r, \; \min \left\{ \mathrm{dp}(l, j) + A_l \mid l \lt r \land A_l \ge A_r \right\} - A_r \right)$$</div> までで止まってしまう。
segment木による実家DPに持ち込みたいが、$A_l \le A_r$な$l$と$A_l \ge A_r$な$l$とが入り乱れてしまうために難しい。
そこで添字を$A_i$の順で整列(覚えておきたい)することを考える。
$\sigma(i) \le \sigma(j) \iff A_i \le A_j$なrank関数$\sigma$を取ると、適当な位置を$+ \infty$で初期化しておくことにより、
<div>$$\mathrm{dp}(r, j + 1) = \min \left( \min \left\{ \mathrm{dp}(\sigma^{-1}(i), j) - A_{\sigma^{-1}(i)} \mid i \lt \sigma(r) \right\} + A_r, \; \min \left\{ \mathrm{dp}(\sigma^{-1}(i), j) + A_{\sigma^{-1}(i)} \mid i \gt \sigma(r) \right\} - A_r \right)$$</div> とできる。
これはsegment木で処理できる形である。
よって$O(NM\log N)$。

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define REP_R(i, n) for (int i = int(n) - 1; (i) >= 0; -- (i))
#define ALL(x) begin(x), end(x)
using ll = long long;
using namespace std;
template <class T> inline void chmin(T & a, T const & b) { a = min(a, b); }

template <class Monoid>
struct segment_tree {
    typedef typename Monoid::underlying_type underlying_type;
    int n;
    vector<underlying_type> a;
    const Monoid mon;
    segment_tree() = default;
    segment_tree(int a_n, underlying_type initial_value = Monoid().unit(), Monoid const & a_mon = Monoid()) : mon(a_mon) {
        n = 1; while (n < a_n) n *= 2;
        a.resize(2 * n - 1, mon.unit());
        fill(a.begin() + (n - 1), a.begin() + ((n - 1) + a_n), initial_value); // set initial values
        REP_R (i, n - 1) a[i] = mon.append(a[2 * i + 1], a[2 * i + 2]); // propagate initial values
    }
    void point_set(int i, underlying_type z) { // 0-based
        a[i + n - 1] = z;
        for (i = (i + n) / 2; i > 0; i /= 2) { // 1-based
            a[i - 1] = mon.append(a[2 * i - 1], a[2 * i]);
        }
    }
    underlying_type range_concat(int l, int r) { // 0-based, [l, r)
        underlying_type lacc = mon.unit(), racc = mon.unit();
        for (l += n, r += n; l < r; l /= 2, r /= 2) { // 1-based loop, 2x faster than recursion
            if (l % 2 == 1) lacc = mon.append(lacc, a[(l ++) - 1]);
            if (r % 2 == 1) racc = mon.append(a[(-- r) - 1], racc);
        }
        return mon.append(lacc, racc);
    }
    underlying_type point_get(int i) { return range_concat(i, i + 1); }
};
struct min_monoid {
    typedef ll underlying_type;
    ll unit() const { return LLONG_MAX; }
    ll append(ll a, ll b) const { return min(a, b); }
};

constexpr ll inf = (ll)1e18 + 9;
int main() {
    // input
    int n, m; cin >> n >> m;
    vector<int> a(n); REP (i,n) cin >> a[i];

    // solve
    vector<ll> acc(n + 1);
    REP (i, n) acc[i + 1] = acc[i] + a[i];
    vector<int> order(n + 1);
    iota(ALL(order), 0);
    sort(ALL(order), [&](int i, int j) { return acc[i] < acc[j]; });
    vector<int> rank(n + 1);
    REP (i, n + 1) rank[order[i]] = i;

    vector<segment_tree<min_monoid> > dp_lo(m + 1, segment_tree<min_monoid>(n + 1, inf));
    vector<segment_tree<min_monoid> > dp_hi(m + 1, segment_tree<min_monoid>(n + 1, inf));
    dp_lo[0].point_set(rank[0], 0);
    dp_hi[0].point_set(rank[0], 0);
    REP (i, n) {
        REP_R (j, m + 1) {
            ll it = inf;
            chmin(it, dp_lo[j].range_concat(0, rank[i + 1])         + acc[i + 1]);
            chmin(it, dp_hi[j].range_concat(rank[i + 1] + 1, n + 1) - acc[i + 1]);
            dp_lo[min(m, j + 1)].point_set(rank[i + 1], it - acc[i + 1]);
            dp_hi[min(m, j + 1)].point_set(rank[i + 1], it + acc[i + 1]);
        }
    }

    // output
    ll answer = dp_lo[m].point_get(rank[n]) + acc[n];
    assert (answer == dp_hi[m].point_get(rank[n]) - acc[n]);
    cout << answer << endl;
    return 0;
}
```
