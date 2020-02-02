---
layout: post
alias: "/blog/2018/01/04/hackerrank-hourrank-25-c/"
title: "HackerRank HourRank 25: C. The Strange Function"
date: "2018-01-04T13:20:00+09:00"
tags: [ "competitive", "writeup", "hackerrank", "hourrank", "segment-tree", "lazy-propagation", "starry-sky-tree", "gcd", "sliding-window" ]
"target_url": [ "https://www.hackerrank.com/contests/hourrank-25/challenges/the-strange-function" ]
---

[editorial](https://www.hackerrank.com/contests/hourrank-25/challenges/the-strange-function/editorial)見ても分からなかったので[kmjp](http://kmjp.hatenablog.jp/entry/2018/01/03/0930)さんのを見た。
editorial中の`with stack`という$2$単語から諸々を読み取るのは私には難しかったです。

## problem

長さ$n$の数列$a$が固定される。$a\_i \in \mathbb{Z}$であり正とも非負とも限らない。
閉区間$I = [l, r]$に対し$f(I) = (\mathrm{gcd}\_{i \in I} a\_i) \cdot \left((\sum\_{i \in I} a\_i) - (\mathrm{max}\_{i \in I} a\_i) \right)$とおく。
$\mathrm{ans} = \max\_I f(I) = \max\_{1 \le l \le r \le n} f([l, r])$を答えよ。

## solution

区間の右端$r$を固定して左端$l$を伸ばしていったとき$\mathrm{gcd}[l, r) = \mathrm{gcd}\_{i \in [l, r)} a\_i$の変化する点は高々$\log a\_{r-1}$個である。
$\mathrm{gcd}[l, r)$は減るならば常に半分以下に減るためである。
$l \in [l\_l, l\_r)$において$\mathrm{gcd}[l, r)$が変化しないと分かれば$\mathrm{gcd}[l\_l, r) \cdot \max\_{l \in [l\_l, l\_r)} \left( \sum a\_i - \max a\_i \right)$だけ考えればよい。
変化する点はsegment木やsparse tableにgcdを乗せての二分探索で全て求まる。
$\mathrm{gcd}[l\_l, r)$は固定なので、$\max\_{l \in [l\_l, l\_r)} \left( \sum a\_i - \max a\_i \right)$を効率良く求めればよい。
$n$点でgcdを二分探索するのでこの部分は$O(n \log n \log a\_{\mathrm{max}})$。

右端$r$を固定して$b\_l = \sum\_{i \in [l, r)} a\_i - \max\_{i \in [l, r)} a\_i$とおく。
これを区間加算と区間最大値を処理できる遅延伝播segment木 (つまりstarry sky tree)で管理する。
$r$をひとつ右に増やした場合を考える。
まず和の部分により全体に$a\_{r - 1}$を加算。
最大値の部分が難しいがslide最小値と同様のテクを使う。
最大値の変化する点をstackに持っておき、このstackからのpopに合わせてsegment木に対する区間加算クエリを発行する。
このpopの回数はpushの回数で抑えられて全体で合計高々$N$回。
segment木の構築や更新でこの部分は$O(n \log n)$。

ちなみに$\mathrm{gcd}[l\_l, r)$が$l\_l$を減らすに従って単調減少することから、$\min\_{l \in [l\_l, l\_r)} b\_l$でなくて$\min\_{l \in [l\_l, r)} b\_l$だけ求めるのでも十分。
これを使うと実装が楽になる。

### 注意

-   gcdの変化する点だけ見ればよいというのは嘘。
    $a + b + c - \max \\{ a, b, c \\} \ge a + b - \max \\{ a, b \\}$は一般に成り立たないため。
    変形すると$c + \max \\{ a, b \\} \ge \max \\{ a, b, c \\}$で、例えば$c$が負の場合には偽になる。
-   愚直解を書いて適当に打ち切るだけでほとんど満点が得られる。
    ジャッジ特性により入力解析も楽なのでそのまま押し込めるはず。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < int(n); ++ (i))
#define REP_R(i, n) for (int i = int(n) - 1; (i) >= 0; -- (i))
using ll = long long;
using namespace std;
template <class T> inline void chmax(T & a, T const & b) { a = max(a, b); }

template <typename UnaryPredicate>
int64_t binsearch(int64_t l, int64_t r, UnaryPredicate p) {
    assert (l <= r);
    -- l;
    while (r - l > 1) {
        int64_t m = l + (r - l) / 2;  // avoid overflow
        (p(m) ? r : l) = m;
    }
    return r;
}

template <typename T>
T gcd(T a, T b) {
    while (a) {
        b %= a;
        swap(a, b);
    }
    return abs(b);
}
template <class Semilattice>
struct sparse_table {
    typedef typename Semilattice::underlying_type underlying_type;
    vector<vector<underlying_type> > table;
    Semilattice lat;
    sparse_table() = default;
    sparse_table(vector<underlying_type> const & data, Semilattice const & a_lat = Semilattice())
            : lat(a_lat) {
        int n = data.size();
        int log_n = 32 - __builtin_clz(n);
        table.resize(log_n, vector<underlying_type>(n));
        table[0] = data;
        REP (k, log_n - 1) {
            REP (i, n) {
                table[k + 1][i] = i + (1ll << k) < n ?
                    lat.append(table[k][i], table[k][i + (1ll << k)]) :
                    table[k][i];
            }
        }
    }
    underlying_type range_concat(int l, int r) const {
        if (l == r) return lat.unit();  // if there is no unit, remove this line
        assert (0 <= l and l < r and r <= table[0].size());
        int k = 31 - __builtin_clz(r - l);  // log2
        return lat.append(table[k][l], table[k][r - (1ll << k)]);
    }
};
struct gcd_semilattice {
    typedef int underlying_type;
    int unit() const { return 0; }
    int append(int a, int b) const { return gcd(a, b); }
};

template <class Monoid, class OperatorMonoid>
struct lazy_propagation_segment_tree { // on monoids
    static_assert (is_same<typename Monoid::underlying_type, typename OperatorMonoid::target_type>::value, "");
    typedef typename Monoid::underlying_type underlying_type;
    typedef typename OperatorMonoid::underlying_type operator_type;
    const Monoid mon;
    const OperatorMonoid op;
    int n;
    vector<underlying_type> a;
    vector<operator_type> f;
    lazy_propagation_segment_tree() = default;
    lazy_propagation_segment_tree(int a_n, underlying_type initial_value = Monoid().unit(), Monoid const & a_mon = Monoid(), OperatorMonoid const & a_op = OperatorMonoid())
            : mon(a_mon), op(a_op) {
        n = 1; while (n <= a_n) n *= 2;
        a.resize(2 * n - 1, mon.unit());
        fill(a.begin() + (n - 1), a.begin() + ((n - 1) + a_n), initial_value); // set initial values
        REP_R (i, n - 1) a[i] = mon.append(a[2 * i + 1], a[2 * i + 2]); // propagate initial values
        f.resize(max(0, (2 * n - 1) - n), op.identity());
    }
    void range_apply(int l, int r, operator_type z) {
        assert (0 <= l and l <= r and r <= n);
        range_apply(0, 0, n, l, r, z);
    }
    void range_apply(int i, int il, int ir, int l, int r, operator_type z) {
        if (l <= il and ir <= r) { // 0-based
            a[i] = op.apply(z, a[i]);
            if (i < f.size()) f[i] = op.compose(z, f[i]);
        } else if (ir <= l or r <= il) {
            // nop
        } else {
            range_apply(2 * i + 1, il, (il + ir) / 2, 0, n, f[i]);
            range_apply(2 * i + 2, (il + ir) / 2, ir, 0, n, f[i]);
            f[i] = op.identity();
            range_apply(2 * i + 1, il, (il + ir) / 2, l, r, z);
            range_apply(2 * i + 2, (il + ir) / 2, ir, l, r, z);
            a[i] = mon.append(a[2 * i + 1], a[2 * i + 2]);
        }
    }
    underlying_type range_concat(int l, int r) {
        assert (0 <= l and l <= r and r <= n);
        return range_concat(0, 0, n, l, r);
    }
    underlying_type range_concat(int i, int il, int ir, int l, int r) {
        if (l <= il and ir <= r) { // 0-based
            return a[i];
        } else if (ir <= l or r <= il) {
            return mon.unit();
        } else {
            return op.apply(f[i], mon.append(
                    range_concat(2 * i + 1, il, (il + ir) / 2, l, r),
                    range_concat(2 * i + 2, (il + ir) / 2, ir, l, r)));
        }
    }
};
struct max_monoid {
    typedef ll underlying_type;
    ll unit() const { return LLONG_MIN; }
    ll append(ll a, ll b) const { return max(a, b); }
};
struct plus_operator_monoid {
    typedef ll underlying_type;
    typedef ll target_type;
    ll identity() const { return 0; }
    ll apply(underlying_type a, target_type b) const { return a + b; }
    ll compose(underlying_type a, underlying_type b) const { return a + b; }
};
typedef lazy_propagation_segment_tree<max_monoid, plus_operator_monoid> starry_sky_tree;


constexpr ll inf = ll(1e18) + 9;
int main() {
    // input
    int n; scanf("%d", &n);
    vector<int> a(n); REP (i, n) scanf("%d", &a[i]);

    // solve
    ll result = - inf;
    sparse_table<gcd_semilattice> table(a);
    starry_sky_tree segtree(n, 0);
    stack<pair<int, int> > stk;
    REP3 (r, 1, n + 1) {
        // update the segment tree
        segtree.range_apply(0, r, a[r - 1]);
        { // update the stack
            int l = r - 1;
            while (not stk.empty() and stk.top().second <= a[r - 1]) {
                int nl, value; tie(nl, value) = stk.top(); stk.pop();
                segtree.range_apply(nl, l, value - a[r - 1]);
                l = nl;
            }
            segtree.range_apply(r - 1, r, - a[r - 1]);
            stk.emplace(l, a[r - 1]);
        }
        { // update the result
            int l = r;
            while (l > 0) {
                int d = table.range_concat(l - 1, r);
                l = binsearch(0, l, [&](int m) {
                    return table.range_concat(m, r) >= d;
                });
                chmax(result, d * segtree.range_concat(l, r));
            }
        }
    }

    // output
    printf("%lld\n", result);
    return 0;
}
```
