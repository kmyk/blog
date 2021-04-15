---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/230/
  - /blog/2017/02/07/yuki-230/
date: "2017-02-07T21:34:02+09:00"
tags: [ "competitive", "writeup", "yukicoder", "segment-tree", "lazy-propagation" ]
"target_url": [ "http://yukicoder.me/problems/no/230" ]
---

# Yukicoder No.230 Splarraay ｽﾌﾟﾗﾚｪｰｲ

以前挑んで失敗した跡があったが、ライブラリ整備してれば流れで書くだけ。

## solution

遅延伝播segment木。$O(N + Q \log N)$。

参考: <https://kimiyuki.net/blog/2017/01/17/segment-tree-requirements/>

## implementation

``` c++
#include <iostream>
#include <vector>
#include <numeric>
#include <array>
#include <functional>
#include <cmath>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using ll = long long;
using namespace std;

template <typename M, typename Q>
struct lazy_propagation_segment_tree { // on monoids
    int n;
    vector<M> a;
    vector<Q> q;
    function<M (M,M)> append_m; // associative
    function<Q (Q,Q)> append_q; // associative, not necessarily commutative
    function<M (Q,M)> apply; // distributive, associative
    M unit_m; // unit
    Q unit_q; // unit
    lazy_propagation_segment_tree() = default;
    lazy_propagation_segment_tree(int a_n, M a_unit_m, Q a_unit_q, function<M (M,M)> a_append_m, function<Q (Q,Q)> a_append_q, function<M (Q,M)> a_apply) {
        n = pow(2,ceil(log2(a_n)));
        a.resize(2*n-1, a_unit_m);
        q.resize(max(0, 2*n-1-n), a_unit_q);
        unit_m = a_unit_m;
        unit_q = a_unit_q;
        append_m = a_append_m;
        append_q = a_append_q;
        apply = a_apply;
    }
    void range_apply(int l, int r, Q z) {
        assert (0 <= l and l <= r and r <= n);
        range_apply(0, 0, n, l, r, z);
    }
    void range_apply(int i, int il, int ir, int l, int r, Q z) {
        if (l <= il and ir <= r) {
            a[i] = apply(z, a[i]);
            if (i < q.size()) q[i] = append_q(z, q[i]);
        } else if (ir <= l or r <= il) {
            // nop
        } else {
            range_apply(2*i+1, il, (il+ir)/2, 0, n, q[i]);
            range_apply(2*i+1, il, (il+ir)/2, l, r, z);
            range_apply(2*i+2, (il+ir)/2, ir, 0, n, q[i]);
            range_apply(2*i+2, (il+ir)/2, ir, l, r, z);
            a[i] = append_m(a[2*i+1], a[2*i+2]);
            q[i] = unit_q;
        }
    }
    M range_concat(int l, int r) {
        assert (0 <= l and l <= r and r <= n);
        return range_concat(0, 0, n, l, r);
    }
    M range_concat(int i, int il, int ir, int l, int r) {
        if (l <= il and ir <= r) {
            return a[i];
        } else if (ir <= l or r <= il) {
            return unit_m;
        } else {
            return apply(q[i], append_m(
                    range_concat(2*i+1, il, (il+ir)/2, l, r),
                    range_concat(2*i+2, (il+ir)/2, ir, l, r)));
        }
    }
};

int main() {
    int n; cin >> n;
    lazy_propagation_segment_tree<array<int,3>,int> segtree(n, {}, -1, [&](array<int,3> a, array<int,3> b) {
        array<int,3> c;
        repeat (i,3) c[i] = a[i] + b[i];
        return c;
    }, [&](int q, int p) {
        if (q == -1) return p;
        return q;
    }, [&](int p, array<int,3> a) {
        if (p == -1) return a;
        array<int,3> b = {};
        if (p == 0) {
            b[0] = 1;
        } else {
            b[p] = whole(accumulate, a, 0);
        }
        return b;
    });
    repeat (i,n) segtree.range_apply(i, i+1, 0);
    ll a = 0, b = 0;
    int q; cin >> q;
    while (q --) {
        int x, l, r; cin >> x >> l >> r; ++ r;
        if (x == 0) {
            array<int,3> it = segtree.range_concat(l, r);
            if (it[1] > it[2]) {
                a += it[1];
            } else if (it[1] < it[2]) {
                b += it[2];
            }
        } else {
            segtree.range_apply(l, r, x);
        }
    }
    array<int,3> it = segtree.range_concat(0, n);
    a += it[1];
    b += it[2];
    cout << a << ' ' << b << endl;
    return 0;
}
```
