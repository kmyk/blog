---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/255/
  - /blog/2017/02/08/yuki-255/
date: "2017-02-08T00:51:48+09:00"
tags: [ "competitive", "writeup", "yukicoder", "segment-tree", "lazy-propagation", "coordinate-compression" ]
"target_url": [ "https://yukicoder.me/problems/no/255" ]
---

# Yukicoder No.255 Splarrraaay ｽﾌﾟﾗｰﾚｪｰｰｲ

前編である[No.230 Splarraay ｽﾌﾟﾗﾚｪｰｲ](http://yukicoder.me/problems/625)を解いた後にそのまま投げたら座圧が必要なの見落としててREが乱立したし、$10^{18}+9$で剰余取るのを忘れててWAで困ったりもした。
剰余取るのが必要なケースはひとつだけっぽいのと$10^{18}+9$という大きな値なので、自分の提出を含めて足せば落ちる提出はありそう。

## solution

座標圧縮 + 遅延伝播segment木。$O(Q \log Q)$。

$N \le 10^{13}$と大きい。クエリを先読みして座標圧縮し、配列の要素には長さの属性を持たせる。

木に与えるクエリは合成ができないといけないが、このため厚みの属性と合成の可否の属性のふたつが必要。
合成の可否とは、「Aの色で厚み2で塗る」と「Aの色で厚み2で塗る」は「Aの色で厚み4で塗る」に合成できるが、「Aの色で厚み2で塗る」と「(Bの色で塗った後に)Aの色で厚み2で塗る」は合成しても「(Bの色で塗った後に)Aの色で厚み2で塗る」にしかならないという区別のため。

$10^{18}+9$での剰余を忘れないように。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <numeric>
#include <array>
#include <map>
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

const ll mod = ll(1e18)+9;
struct state_t {
    ll size;
    array<ll,5> acc;
};
struct query_t {
    enum { UNIT, LENGTH, FILL } type;
    ll arg1;
    int arg2;
    bool arg3;
};
int main() {
    // input
    ll n; int q; cin >> n >> q;
    vector<int> x(q); vector<ll> l(q), r(q); repeat (i,q) { cin >> x[i] >> l[i] >> r[i]; ++ r[i]; }
    // prepare
    map<ll,int> compress; {
        vector<ll> ps;
        ps.push_back(0);
        ps.push_back(n);
        repeat (i,q) {
            ps.push_back(l[i]);
            ps.push_back(r[i]);
        }
        compress = coordinate_compression_map(ps);
    }
    lazy_propagation_segment_tree<state_t,query_t> segtree(compress[n], (state_t) { 0, {} }, (query_t) { query_t::UNIT }, [&](state_t const & a, state_t const & b) {
        state_t c;
        c.size = a.size + b.size;
        repeat (i,5) c.acc[i] = a.acc[i] + b.acc[i];
        return c;
    }, [&](query_t q, query_t p) {
        if (q.type == query_t::UNIT) return p;
        if (p.type == query_t::UNIT) return q;
        assert (q.type == query_t::FILL);
        assert (p.type == query_t::FILL);
        if (q.arg1 == p.arg1) { // if same color
            if (not q.arg3) { // if not reset
                q.arg2 += p.arg2;
                q.arg3 = p.arg3;
            }
        } else {
            q.arg3 = true; // reset
        }
        return q;
    }, [&](query_t p, state_t a) {
        if (p.type == query_t::UNIT) return a;
        if (p.type == query_t::LENGTH) return (state_t) { p.arg1, {} };
        int color = p.arg1;
        int depth = p.arg2;
        bool reset = p.arg3;
        state_t b = {};
        b.size = a.size;
        b.acc[color] = ((reset ? 0 : a.acc[color]) + depth * a.size % mod) % mod;
        return b;
    });
    for (auto cur = compress.begin(), nxt = ++ compress.begin(); nxt != compress.end(); ++ cur, ++ nxt) {
        assert (cur->second + 1 == nxt->second);
        segtree.range_apply(cur->second, nxt->second, (query_t) { query_t::LENGTH, nxt->first - cur->first });
        segtree.range_concat(cur->second, nxt->second);
    }
    // solve
    ll acc[5] = {};
    repeat (i,q) {
        if (x[i] == 0) {
            state_t it = segtree.range_concat(compress[l[i]], compress[r[i]]);
            int j = whole(max_element, it.acc) - it.acc.begin();
            if (whole(count, it.acc, it.acc[j]) == 1) {
                acc[j] = (acc[j] + it.acc[j]) % mod;
            }
        } else {
            segtree.range_apply(compress[l[i]], compress[r[i]], (query_t) { query_t::FILL, x[i]-1, 1, false });
        }
    }
    state_t it = segtree.range_concat(compress[0], compress[n]);
    repeat (i,5) acc[i] = (acc[i] + it.acc[i]) % mod;
    // output
    repeat (i,5) cout << acc[i] << ' '; cout << endl;
    return 0;
}
```
