---
layout: post
redirect_from:
  - /writeup/algo/atcoder/dwacon2018-final-b/
  - /blog/2018/02/14/dwacon2018-final-b/
date: "2018-02-14T02:32:26+09:00"
tags: [ "competitive", "writeup", "atcoder", "dwacon", "dp", "binary-indexed-tree", "coordinate-compression" ]
"target_url": [ "https://beta.atcoder.jp/contests/dwacon2018-final-open/tasks/dwacon2018_final_b" ]
---

# 第4回 ドワンゴからの挑戦状 本選: B - だんだん強く

$800$点は多すぎる気がする

## solution

座圧して実家。$O(KN\log N)$。

$i$日目まで過ぎて最後に音量$v$で放送し$k$回ルール違反している状態でのそれまでの放送回数の最大値を$\mathrm{dp}(i, v, k)$。
漸化式は$\mathrm{dp}(i + 1, v, k) = \max \\{ \max \\{ \mathrm{dp}(i, v', k) \mid v' \lt v \\}, \max \\{ \mathrm{dp}(i, v', k - 1) \mid v' \in \mathbb{N} \\} \\}$。


## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define REP_R(i, n) for (int i = int(n) - 1; (i) >= 0; -- (i))
#define ALL(x) begin(x), end(x)
using namespace std;

template <typename T>
map<T, int> coordinate_compression_map(vector<T> const & xs) {
    int n = xs.size();
    vector<int> ys(n);
    iota(ALL(ys), 0);
    sort(ALL(ys), [&](int i, int j) { return xs[i] < xs[j]; });
    map<T, int> f;
    for (int i : ys) {
        if (not f.count(xs[i])) { // make unique
            int j = f.size();
            f[xs[i]] = j; // f[xs[i]] has a side effect, increasing the f.size()
        }
    }
    return f;
}
template <typename T>
vector<int> apply_compression(map<T, int> const & f, vector<T> const & xs) {
    int n = xs.size();
    vector<int> ys(n);
    REP (i, n) ys[i] = f.at(xs[i]);
    return ys;
}

template <typename Monoid>
struct binary_indexed_tree { // on monoid
    typedef typename Monoid::underlying_type underlying_type;
    vector<underlying_type> data;
    Monoid mon;
    binary_indexed_tree(size_t n, Monoid const & a_mon = Monoid()) : mon(a_mon) {
        data.resize(n, mon.unit());
    }
    void point_append(size_t i, underlying_type z) { // data[i] += z
        for (size_t j = i + 1; j <= data.size(); j += j & -j) data[j - 1] = mon.append(data[j - 1], z);
    }
    underlying_type initial_range_concat(size_t i) { // sum [0, i)
        underlying_type acc = mon.unit();
        for (size_t j = i; 0 < j; j -= j & -j) acc = mon.append(data[j - 1], acc);
        return acc;
    }
};
struct max_monoid {
    typedef int underlying_type;
    int unit() const { return 0; }
    int append(int a, int b) const { return max(a, b); }
};

int main() {
    // input
    int n, k; cin >> n >> k;
    vector<int> v(n);
    REP (i, n) cin >> v[i];

    // solve
    v = apply_compression(coordinate_compression_map(v), v);
    int max_v = *max_element(ALL(v));
    vector<binary_indexed_tree<max_monoid> > dp(k + 1, binary_indexed_tree<max_monoid>(max_v + 1));
    for (int v_i : v) {
        REP_R (j, k + 1) {
            dp[j].point_append(v_i, dp[j].initial_range_concat(v_i) + 1);
            if (j >= 1) {
                dp[j].point_append(v_i, dp[j - 1].initial_range_concat(max_v + 1) + 1);
            }
        }
    }

    // output
    int result = dp[k].initial_range_concat(max_v + 1);
    cout << result << endl;
    return 0;
}
```
