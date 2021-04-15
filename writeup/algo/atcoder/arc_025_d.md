---
layout: post
date: 2018-09-14T02:48:49+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "linarity", "matrix", "segment-tree", "dynamic-construction" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc025/tasks/arc025_4" ]
redirect_from:
  - /writeup/algo/atcoder/arc_025_d/
  - /writeup/algo/atcoder/arc-025-d/
---

# AtCoder Regular Contest 025: D - コンセント

<!-- {% raw %} -->

## 解法

線形DPを行列で書いて動的構築segment木に乗せる(典型)。
$O(N 2^{3H} \log W)$。
$H \le 2$であることは本質でなくて$H \le 5$とかでも面倒になるだけでできる。

## メモ

典型やるだけ感がつよいので点数的には700点か800点ぐらいだと思う

## 実装

``` c++
#include <algorithm>
#include <array>
#include <cassert>
#include <climits>
#include <deque>
#include <iostream>
#include <map>
#include <numeric>
#include <stack>
#include <vector>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define ALL(x) begin(x), end(x)
using ll = long long;
using namespace std;

template <typename T, size_t H, size_t W = H>
using matrix = array<array<T, W>, H>;
template <typename T, size_t A, size_t B, size_t C>
matrix<T, A, C> operator * (matrix<T, A, B> const & a, matrix<T, B, C> const & b) {
    matrix<T, A, C> c = {};
    REP (y, A) REP (z, B) REP (x, C) c[y][x] += a[y][z] * b[z][x];
    return c;
}
template <typename T, size_t H, size_t W>
array<T, H> operator * (matrix<T, H, W> const & a, array<T, W> const & b) {
    array<T, H> c = {};
    REP (y, H) REP (z, W) c[y] += a[y][z] * b[z];
    return c;
}
template <typename T, size_t N>
matrix<T, N, N> matrix_unit() {
    matrix<T, N, N> a = {};
    REP (i, N) a[i][i] = 1;
    return a;
}
template <typename T, size_t N>
matrix<T, N, N> matrix_pow(matrix<T, N, N> x, ll k) {
    matrix<T, N, N> y = matrix_unit<T, N>();
    for (ll i = 1; i <= k; i <<= 1) {
        if (k & i) y = y * x;
        x = x * x;
    }
    return y;
}

template <int32_t MOD>
struct mint {
    int64_t data;
    mint() = default;
    mint(int64_t value) : data(value) {}
    inline mint<MOD> operator + (mint<MOD> other) const { int64_t c = this->data + other.data; return mint<MOD>(c >= MOD ? c - MOD : c); }
    inline mint<MOD> operator - (mint<MOD> other) const { int64_t c = this->data - other.data; return mint<MOD>(c <    0 ? c + MOD : c); }
    inline mint<MOD> operator * (mint<MOD> other) const { int64_t c = this->data * int64_t(other.data) % MOD; return mint<MOD>(c < 0 ? c + MOD : c); }
    inline mint<MOD> & operator += (mint<MOD> other) { this->data += other.data; if (this->data >= MOD) this->data -= MOD; return *this; }
    inline mint<MOD> & operator -= (mint<MOD> other) { this->data -= other.data; if (this->data <    0) this->data += MOD; return *this; }
    inline mint<MOD> & operator *= (mint<MOD> other) { this->data = this->data * int64_t(other.data) % MOD; if (this->data < 0) this->data += MOD; return *this; }
};

template <class Monoid>
struct dynamic_segment_tree { // on monoid
    typedef Monoid monoid_type;
    typedef typename Monoid::underlying_type underlying_type;
    struct node_t {
        int left, right; // indices on pool
        underlying_type value;
    };
    deque<node_t> pool;
    stack<int> bin;
    int root; // index
    ll width; // of the tree
    int size; // the number of leaves
    Monoid mon;
    dynamic_segment_tree(Monoid const & a_mon = Monoid()) : mon(a_mon) {
        node_t node = { -1, -1, mon.unit() };
        pool.push_back(node);
        root = 0;
        width = 1;
        size = 1;
    }
protected:
    int create_node(int parent, bool is_right) {
        // make a new node
        int i;
        if (bin.empty()) {
            i = pool.size();
            node_t node = { -1, -1, mon.unit() };
            pool.push_back(node);
        } else {
            i = bin.top();
            bin.pop();
            pool[i] = { -1, -1, mon.unit() };
        }
        // link from the parent
        assert (parent != -1);
        int & ptr = is_right ? pool[parent].right : pool[parent].left;
        assert (ptr == -1);
        ptr = i;
        return i;
    }
    underlying_type get_value(int i) {
        return i == -1 ? mon.unit() : pool[i].value;
    }
public:
    void point_set(ll i, underlying_type z) {
        assert (0 <= i);
        while (width <= i) {
            node_t node = { root, -1, pool[root].value };
            root = pool.size();
            pool.push_back(node);
            width *= 2;
        }
        point_set(root, -1, false, 0, width, i, z);
    }
    void point_set(int i, int parent, bool is_right, ll il, ll ir, ll j, underlying_type z) {
        if (il == j and ir == j + 1) { // 0-based
            if (i == -1) {
                i = create_node(parent, is_right);
                size += 1;
            }
            pool[i].value = z;
        } else if (ir <= j or j + 1 <= il) {
            // nop
        } else {
            if (i == -1) i = create_node(parent, is_right);
            point_set(pool[i].left,  i, false, il, (il + ir) / 2, j, z);
            point_set(pool[i].right, i, true,  (il + ir) / 2, ir, j, z);
            pool[i].value = mon.append(get_value(pool[i].left), get_value(pool[i].right));
        }
    }
    underlying_type range_concat(ll l, ll r) {
        assert (0 <= l and l <= r);
        if (width <= l) return mon.unit();
        return range_concat(root, 0, width, l, min(width, r));
    }
    underlying_type range_concat(int i, ll il, ll ir, ll l, ll r) {
        if (i == -1) return mon.unit();
        if (l <= il and ir <= r) { // 0-based
            return pool[i].value;
        } else if (ir <= l or r <= il) {
            return mon.unit();
        } else {
            return mon.append(
                    range_concat(pool[i].left,  il, (il + ir) / 2, l, r),
                    range_concat(pool[i].right, (il + ir) / 2, ir, l, r));
        }
    }
};

constexpr int MOD = 1e9 + 7;

matrix<mint<MOD>, 4> get_dp_step(int t) {
    matrix<mint<MOD>, 4> dp = {};
    bool vr = not t;
    REP (s, 0x4) {
        bool hr0 = not (s & 0b01) and not (t & 0b01);
        bool hr1 = not (s & 0b10) and not (t & 0b10);
        // ??
        // ??
        dp[t][s] += 1;
        if (vr) {
            // ?^
            // ?v
            dp[0b11][s] += 1;
        }
        if (hr0) {
            // <>
            // ??
            dp[(t & 0b10) + 0b01][s] += 1;
        }
        if (hr1) {
            // ??
            // <>
            dp[0b10 + (t & 0b01)][s] += 1;
        }
        if (hr0 and hr1) {
            // <>
            // <>
            dp[0b11][s] += 1;
        }
    }
    return dp;
}

struct dp_monoid {
    const int h;
    dp_monoid(int h_)
            : h(h_) {
        assert (h == 1 or h == 2);
    }

    typedef tuple<ll, ll, matrix<mint<MOD>, 4> > underlying_type;
    underlying_type unit() const {
        return make_tuple(LLONG_MIN, LLONG_MIN, matrix_unit<mint<MOD>, 4>());
    }
    underlying_type append(underlying_type const & a, underlying_type const & b) const {
        ll al, ar; matrix<mint<MOD>, 4> a1; tie(al, ar, a1) = a;
        ll bl, br; matrix<mint<MOD>, 4> b1; tie(bl, br, b1) = b;
        if (al == LLONG_MIN) return b;
        if (bl == LLONG_MIN) return a;
        assert (al < ar and ar <= bl and bl < br);
        const int t = (h == 1 ? 0b10 : 0b00);
        auto c1 = b1 * matrix_pow(get_dp_step(t), bl - ar) * a1;
        return make_tuple(al, br, c1);
    }
};

int main() {
    // input
    int h; ll w; cin >> h >> w;
    int n; cin >> n;

    assert (h == 1 or h == 2);
    map<ll, int> f;
    dynamic_segment_tree<dp_monoid> dp((dp_monoid(h)));
    dp.point_set(0,     make_tuple(    0,     1, matrix_unit<mint<MOD>, 4>()));
    dp.point_set(w + 1, make_tuple(w + 1, w + 2, matrix_unit<mint<MOD>, 4>()));

    while (n --) {
        // query
        int y; ll x; cin >> y >> x;
        -- y;
        if (not f.count(x)) {
            f[x] = (h == 1 ? 0b10 : 0b00);
        }
        f[x] ^= (1 << y);
        dp.point_set(x, make_tuple(x, x + 1, get_dp_step(f[x])));

        // output
        auto mat = dp.range_concat(0, w + 2);
        array<mint<MOD>, 4> vec = {{ 0, 0, 0, 1 }};
        auto it = get<2>(mat) * vec;
        cout << accumulate(ALL(it), mint<MOD>()).data << endl;
    }
    return 0;
}
```

<!-- {% endraw %} -->
