---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc_056_d/
  - /writeup/algo/atcoder/arc-056-d/
  - /blog/2017/05/27/arc-056-d/
date: "2017-05-27T03:24:10+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "dp", "segment-tree" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc056/tasks/arc056_d" ]
---

# AtCoder Regular Contest 056: D - サケノミ

## solution

動的計画法。時刻$t$でグラスが全て空なとき(それ以前はなかったことにして)それ以降を最適に飲んだときの美味しさの総和の最大値を$\mathrm{dp}\_t$とする。
単純には後ろからそのまま計算していき$T = \max t\_{i,j}$に対し$O(T^2 \sum M\_i)$。
漸化式は$\mathrm{dp}\_t = \max \\{ \mathrm{drinks}[t, t') + \mathrm{dp}\_{t'} \mid t \lt t' \\}$だが、$\mathrm{dp'}\_{\bullet,t'} = \mathrm{drinks}[\bullet, t') + \mathrm{dp}\_{t'}$と取りなおして区間add/区間maxのsegment木でまとめて管理すれば$O(T \log T + \sum M\_i)$。

## implementation

遅延伝播segment木をmonoid/magma準同型で整理したらすごく良かった。
座圧は必須でない。

``` c++
#include <cstdio>
#include <vector>
#include <algorithm>
#include <numeric>
#include <map>
#include <type_traits>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_reverse(i,n) for (int i = (n)-1; (i) >= 0; --(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using ll = long long;
using namespace std;

template <typename T>
map<T,int> coordinate_compression_map(vector<T> const & xs) {
    int n = xs.size();
    vector<int> ys(n);
    whole(iota, ys, 0);
    whole(sort, ys, [&](int i, int j) { return xs[i] < xs[j]; });
    map<T,int> f;
    for (int i : ys) {
        if (not f.count(xs[i])) { // make unique
            int j = f.size();
            f[xs[i]] = j; // f[xs[i]] has a side effect, increasing the f.size()
        }
    }
    return f;
}

template <class Monoid, class MagmaEndomorphism>
struct lazy_propagation_segment_tree { // on monoids
    static_assert (is_same<typename Monoid::type, typename MagmaEndomorphism::underlying_type>::value, "");
    typedef typename Monoid::type T;
    typedef typename MagmaEndomorphism::type F;
    Monoid mon;
    MagmaEndomorphism endo;
    int n;
    vector<T> a;
    vector<F> f;
    lazy_propagation_segment_tree() = default;
    lazy_propagation_segment_tree(int a_n, Monoid const & a_mon = Monoid(), MagmaEndomorphism const & a_endo = MagmaEndomorphism())
            : mon(a_mon), endo(a_endo) {
        n = 1; while (n <= a_n) n *= 2;
        a.resize(2*n-1, mon.unit());
        f.resize(max(0, 2*n-1-n), endo.identity());
    }
    void range_apply(int l, int r, F z) {
        assert (0 <= l and l <= r and r <= n);
        range_apply(0, 0, n, l, r, z);
    }
    void range_apply(int i, int il, int ir, int l, int r, F z) {
        if (l <= il and ir <= r) {
            a[i] = endo.apply(z, a[i]);
            if (i < f.size()) f[i] = endo.compose(z, f[i]);
        } else if (ir <= l or r <= il) {
            // nop
        } else {
            range_apply(2*i+1, il, (il+ir)/2, 0, n, f[i]);
            range_apply(2*i+1, il, (il+ir)/2, l, r, z);
            range_apply(2*i+2, (il+ir)/2, ir, 0, n, f[i]);
            range_apply(2*i+2, (il+ir)/2, ir, l, r, z);
            a[i] = mon.append(a[2*i+1], a[2*i+2]);
            f[i] = endo.identity();
        }
    }
    T range_concat(int l, int r) {
        assert (0 <= l and l <= r and r <= n);
        return range_concat(0, 0, n, l, r);
    }
    T range_concat(int i, int il, int ir, int l, int r) {
        if (l <= il and ir <= r) {
            return a[i];
        } else if (ir <= l or r <= il) {
            return mon.unit();
        } else {
            return endo.apply(f[i], mon.append(
                    range_concat(2*i+1, il, (il+ir)/2, l, r),
                    range_concat(2*i+2, (il+ir)/2, ir, l, r)));
        }
    }
};

struct max_t {
    typedef ll type;
    ll unit() const { return 0; }
    ll append(ll a, ll b) const { return max(a, b); }
};

struct plus_endomorphism_t {
    typedef ll underlying_type;
    typedef ll type;
    type identity() const {
        return 0;
    }
    type compose(type a, type b) const {
        return a + b;
    }
    underlying_type apply(type a, underlying_type b) const {
        return a + b;
    }
};

int main() {
    // input
    int n; scanf("%d", &n);
    vector<int> w(n); repeat (i, n) scanf("%d", &w[i]);
    vector<vector<int> > t(n);
    repeat (i, n) {
        int m; scanf("%d", &m);
        t[i].resize(m);
        repeat (j, m) scanf("%d", &t[i][j]);
    }
    // solve
    map<int, int> compress; {
        vector<int> xs;
        repeat (i, n) {
            xs.insert(xs.end(), t[i].begin(), t[i].end());
        }
        compress = coordinate_compression_map(xs);
    }
    int t_size = compress.size();
    vector<vector<int> > at(t_size);
    repeat (i, n) {
        repeat (j, t[i].size()) {
            at[compress[t[i][j]]].push_back(i);
        }
    }
    lazy_propagation_segment_tree<max_t, plus_endomorphism_t> segtree(t_size + 1);
    vector<int> last(n, t_size);
    repeat_reverse (i, t_size) {
        for (int k : at[i]) {
            segtree.range_apply(i+1, last[k] + 1, w[k]);
            last[k] = i;
        }
        ll acc = max(0ll, segtree.range_concat(i+1, t_size + 1));
        segtree.range_apply(i, i+1, acc);
    }
    // output
    ll result = segtree.range_concat(0, 0+1);
    printf("%lld\n", result);
    return 0;
}
```
