---
layout: post
redirect_from:
  - /writeup/algo/atcoder/yahoo-procon-2017-qual-d/
  - /blog/2017/03/07/yahoo-procon-2017-qual-d/
date: "2017-03-07T17:21:10+09:00"
tags: [ "competitive", "writeup", "atcoder", "yahoo-procon", "segment-tree", "binary-indexed-tree", "coodinate-compression", "batch" ]
"target_url": [ "https://beta.atcoder.jp/contests/yahoo-procon2017-qual/tasks/yahoo_procon2017_qual_d" ]
---

# 「みんなのプロコン」: D - 工場

$26$位で予選通過。順位表の前後に強い人が並んでてちょっと嬉しい。unratedだけど。

## solution

segment tree + 座標圧縮。binary indexed treeでもよい。$O(Q \log Q)$。

$l$日目から$r$日目までの区間$[l,r)$をsegment木で管理することを考える。
区間$[l,r)$に対し、$l$日目で在庫が$0$として($r$日目に余る在庫, $[l,r)$日間で対応できず無視される注文, $[l,r)$日間で成立する取引)の$3$つ組を割り当てる。
この情報は$O(1)$で合成できる。

ただし日数は最大$10^9$になるので、愚直に$O(\max_i D_i \log \max_i D_i)$とはできない。
そこでクエリを先読みし座標圧縮しておく。これで$O(Q \log Q)$になる。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <numeric>
#include <unordered_map>
#include <functional>
#include <cmath>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using ll = long long;
using namespace std;

unordered_map<int,int> coordinate_compression_map(vector<int> const & xs) {
    int n = xs.size();
    vector<int> ys(n);
    whole(iota, ys, 0);
    whole(sort, ys, [&](int i, int j) { return xs[i] < xs[j]; });
    unordered_map<int,int> f;
    for (int i : ys) {
        if (not f.count(xs[i])) { // make unique
            int j = f.size();
            f[xs[i]] = j; // f[xs[i]] has a side effect, increasing the f.size()
        }
    }
    return f;
}

template <typename T>
struct segment_tree { // on monoid
    int n;
    vector<T> a;
    function<T (T,T)> append; // associative
    T unit; // unit
    segment_tree() = default;
    segment_tree(int a_n, T a_unit, function<T (T,T)> a_append) {
        n = pow(2,ceil(log2(a_n)));
        a.resize(2*n-1, a_unit);
        unit = a_unit;
        append = a_append;
    }
    void point_update(int i, T z) {
        a[i+n-1] = z;
        for (i = (i+n)/2; i > 0; i /= 2) {
            a[i-1] = append(a[2*i-1], a[2*i]);
        }
    }
    T range_concat(int l, int r) {
        return range_concat(0, 0, n, l, r);
    }
    T range_concat(int i, int il, int ir, int l, int r) {
        if (l <= il and ir <= r) {
            return a[i];
        } else if (ir <= l or r <= il) {
            return unit;
        } else {
            return append(
                    range_concat(2*i+1, il, (il+ir)/2, l, r),
                    range_concat(2*i+2, (il+ir)/2, ir, l, r));
        }
    }
};
struct node_t {
    ll goods, order, accepted;
};

int main() {
    int q_size, k; cin >> q_size >> k;
    vector<array<int,3> > q(q_size);
    vector<int> d(q_size);
    repeat (i,q_size) {
        cin >> q[i][0];
        if (q[i][0] == 1) {
            cin >> q[i][1] >> q[i][2];
        } else if (q[i][0] == 2) {
            cin >> q[i][1];
        }
        d[i] = q[i][1];
    }
    whole(sort, d);
    d.erase(whole(unique, d), d.end());
    unordered_map<int,int> compress = coordinate_compression_map(d);
    segment_tree<node_t> segtree(q_size, (node_t) { 0, 0, 0 }, [&](node_t const & a, node_t const & b) {
        node_t c;
        ll delta = min(a.goods, b.order);
        c.goods = a.goods + b.goods - delta;
        c.order = a.order + b.order - delta;
        c.accepted = a.accepted + b.accepted + delta;
        return c;
    });
    repeat (i,d.size()) {
        ll delta = k * ll(d[i] - (i == 0 ? 0 : d[i-1]));
        segtree.point_update(i, (node_t) { delta, 0, 0 });
    }
    repeat (i,q_size) {
        int j = compress[q[i][1]];
        if (q[i][0] == 1) {
            node_t a = segtree.range_concat(j, j+1);
            ll delta = min<ll>(a.goods, q[i][2]);
            a.goods -= delta;
            a.order += q[i][2] - delta;
            a.accepted += delta;
            segtree.point_update(j, a);
        } else if (q[i][0] == 2) {
            node_t a = segtree.range_concat(0, j+1);
            cout << a.accepted << endl;
        }
    }
    return 0;
}
```
