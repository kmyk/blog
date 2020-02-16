---
layout: post
alias: "/blog/2018/01/01/utpc-2012-h/"
date: "2018-01-01T10:51:19+09:00"
tags: [ "competitive", "writeup", "utpc", "atcoder", "schduling", "doubling", "query", "segment-tree", "coodinate-compression" ]
"target_url": [ "https://beta.atcoder.jp/contests/utpc2012/tasks/utpc2012_08" ]
---

# 東京大学プログラミングコンテスト2012: H - 区間スケジューリングクエリ

## 反省

もちろん解法に嘘はないが、辿り着くまでの形がなんだか嘘解法っぽい。
解けず。嘘解法屋としては解きたかった。
愚直$O(NQ)$は貪欲ですねというのを確認しておらず、この点はだめ。
実家DPを考えていた。

## solution

愚直解は$O(NQ)$貪欲。
座標圧縮し左から舐めてその時点で使える中で$R\_i$の小さい順に使っていく。
この貪欲をよく眺めると、ある区間を使ったときに次に使う区間は一意に定まる。
これを事前に求めておけばdoublingにより$O(N)$が$O(\log N)$に落ちる。
全体で$((N + Q)\log N)$。

## implementation

editorialが二分探索と言ってるところは複数あるがどれも二分探索の方法が分からなかったのでsegment木で実家した。

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

template <typename T>
vector<T> apply_permutation(vector<int> const & sigma, vector<T> const & xs) {
    int n = sigma.size();
    vector<T> ys(n);
    REP (i, n) ys[i] = xs[sigma[i]];
    return ys;
}

template <class OperatorMonoid>
struct dual_segment_tree {
    typedef typename OperatorMonoid::underlying_type operator_type;
    typedef typename OperatorMonoid::target_type underlying_type;
    int n;
    vector<operator_type> f;
    vector<underlying_type> a;
    OperatorMonoid op;
    dual_segment_tree() = default;
    dual_segment_tree(int a_n, underlying_type initial_value, OperatorMonoid const & a_op = OperatorMonoid()) : op(a_op) {
        n = 1; while (n < a_n) n *= 2;
        a.resize(n, initial_value);
        f.resize(n-1, op.unit());
    }
    underlying_type point_get(int i) { // 0-based
        underlying_type acc = a[i];
        for (i = (i+n)/2; i > 0; i /= 2) { // 1-based
            acc = op.apply(f[i-1], acc);
        }
        return acc;
    }
    void range_apply(int l, int r, operator_type z) { // 0-based, [l, r)
        assert (0 <= l and l <= r and r <= n);
        range_apply(0, 0, n, l, r, z);
    }
    void range_apply(int i, int il, int ir, int l, int r, operator_type z) {
        if (l <= il and ir <= r) { // 0-based
            if (i < f.size()) {
                f[i] = op.append(z, f[i]);
            } else {
                a[i-n+1] = op.apply(z, a[i-n+1]);
            }
        } else if (ir <= l or r <= il) {
            // nop
        } else {
            range_apply(2*i+1, il, (il+ir)/2, 0, n, f[i]);
            range_apply(2*i+2, (il+ir)/2, ir, 0, n, f[i]);
            f[i] = op.unit();
            range_apply(2*i+1, il, (il+ir)/2, l, r, z);
            range_apply(2*i+2, (il+ir)/2, ir, l, r, z);
        }
    }
};
struct min_operator_monoid {
    typedef int underlying_type;
    typedef int target_type;
    int unit() const { return INT_MAX; }
    int append(int a, int b) const { return min(a, b); }
    int apply(int a, int b) const { return min(a, b); }
};

struct doubling_table {
    vector<vector<int> > table;
    doubling_table() = default;
    doubling_table(vector<int> const & next, int size = -1) {
        int n = next.size();
        {
            auto it = minmax_element(ALL(next));
            assert (0 <= *(it.first) and *(it.second) <= n);
        }
        if (size == -1) {
            size = max<int>(1, ceil(log2(n)));
        }
        table.resize(size);
        table[0] = next;
        REP (k, size - 1) {
            table[k + 1].resize(n, n);
            REP (i, n) if (table[k][i] != n) {
                table[k + 1][i] = table[k][table[k][i]];
            }
        }
    }
};

int main() {
    // input
    int n, q; scanf("%d%d", &n, &q);
    vector<int> il(n), ir(n); REP (i, n) scanf("%d%d", &il[i], &ir[i]);
    vector<int> ql(q), qr(q); REP (i, q) scanf("%d%d", &ql[i], &qr[i]);
    // prepare
    // // compress values
    vector<int> points;
    copy(ALL(il), back_inserter(points));
    copy(ALL(ir), back_inserter(points));
    copy(ALL(ql), back_inserter(points));
    copy(ALL(qr), back_inserter(points));
    auto compress = coordinate_compression_map(points);
    il = apply_compression(compress, il);
    ir = apply_compression(compress, ir);
    ql = apply_compression(compress, ql);
    qr = apply_compression(compress, qr);
    int k = compress.size();
    // // reorder with ir
    vector<int> order_ir(n);
    iota(ALL(order_ir), 0);
    sort(ALL(order_ir), [&](int i, int j) { return ir[i] < ir[j]; });
    il = apply_permutation(order_ir, il);
    ir = apply_permutation(order_ir, ir);
    // // prepare greedy
    dual_segment_tree<min_operator_monoid> segtree(k, n);
    vector<int> next(n);
    REP_R (i, n) {
        next[i] = segtree.point_get(ir[i]);
        segtree.range_apply(0, il[i] + 1, i);
    }
    doubling_table doubling(next);
    // solve
    REP (i, q) {
        int result = 0;
        int j = segtree.point_get(ql[i]);
        if (j < n) {
            REP_R (k, doubling.table.size()) {
                int nj = doubling.table[k][j];
                if (nj < n and ir[nj] <= qr[i]) {
                    j = nj;
                    result += 1 << k;
                }
            }
            while (j < n and ir[j] <= qr[i]) {
                j = next[j];
                result += 1;
            }
        }
        // output
        printf("%d\n", result);
    }
    return 0;
}
```
