---
redirect_from:
  - /writeup/algo/codeforces/1037-f/
layout: post
date: 2018-09-03T02:06:04+09:00
tags: [ "competitive", "writeup", "codeforces", "segment-tree", "divide-and-conquer" ]
"target_url": [ "http://codeforces.com/contest/1037/problem/F" ]
---

# Manthan, Codefest 18 (rated, Div. 1 + Div. 2): F. Maximum Reduction

## 解法

最大値の位置で列を分割(典型)できて再帰。
$a_i = i$ などがコーナーとなるのでsegment木などで最大値+位置な区間クエリを処理する。
$O(N \log N)$。

問題文中の関数$z(a, k)$は、列$a$中の長さ$k$の部分列それぞれの最大値を並べて列$b$を作り$z(b, k) + \sum b_i$を結果とする。
具体例を見ると早い。
例えば列$a = ( 1 2 3 2 9 3 4 5 6 7 )$に対しては以下のように進む。

```
1 2 3 2 9 3 4 5 6 7
  3 3 9 9 9 5 6 7
    9 9 9 9 9 7
      9 9 9 9
        9 9
```

この山は以下のようなふたつの山と$15$個の$9$とに分解できる。

```
1 2 3 2   3 4 5 6 7
  3 3       5 6 7
              7
```

このような分割を再帰的にやれば、最大値の位置の取得が$O(\log N)$になるよう準備して$O(N \log N)$で解ける。

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define REP_R(i, n) for (int i = int(n) - 1; (i) >= 0; -- (i))
using ll = long long;
using namespace std;

template <int32_t MOD>
struct mint {
    int64_t data;
    mint() = default;
    mint(int64_t value) : data(value) {}
    inline mint<MOD> operator + (mint<MOD> other) const { int64_t c = this->data + other.data; return mint<MOD>(c >= MOD ? c - MOD : c); }
    inline mint<MOD> operator * (mint<MOD> other) const { int64_t c = this->data * int64_t(other.data) % MOD; return mint<MOD>(c < 0 ? c + MOD : c); }
    inline mint<MOD> & operator += (mint<MOD> other) { this->data += other.data; if (this->data >= MOD) this->data -= MOD; return *this; }
    inline mint<MOD> & operator *= (mint<MOD> other) { this->data = this->data * int64_t(other.data) % MOD; if (this->data < 0) this->data += MOD; return *this; }
};

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
        assert (0 <= i and i <= n);
        a[i + n - 1] = z;
        for (i = (i + n) / 2; i > 0; i /= 2) { // 1-based
            a[i - 1] = mon.append(a[2 * i - 1], a[2 * i]);
        }
    }
    underlying_type range_concat(int l, int r) { // 0-based, [l, r)
        assert (0 <= l and l <= r and r <= n);
        underlying_type lacc = mon.unit(), racc = mon.unit();
        for (l += n, r += n; l < r; l /= 2, r /= 2) { // 1-based loop, 2x faster than recursion
            if (l % 2 == 1) lacc = mon.append(lacc, a[(l ++) - 1]);
            if (r % 2 == 1) racc = mon.append(a[(-- r) - 1], racc);
        }
        return mon.append(lacc, racc);
    }
};
struct max_monoid {
    typedef pair<int, int> underlying_type;
    underlying_type unit() const { return make_pair(INT_MIN, INT_MIN); }
    underlying_type append(underlying_type a, underlying_type b) const { return max(a, b); }
};

constexpr int MOD = 1e9 + 7;

ll sum_b_size(ll n, ll k) {
    ll depth = (n + k - 2) / (k - 1);
    ll sum_a_size = depth * n - depth * (depth - 1) * (k - 1) / 2;
    return sum_a_size - n;
}

mint<MOD> solve(int n, int k, vector<int> const & a) {
    segment_tree<max_monoid> segtree(n);
    REP (i, n) {
        segtree.point_set(i, make_pair(a[i], i));
    }

    mint<MOD> ans = 0;
    stack<pair<int, int> > stk;
    stk.emplace(0, n);
    while (not stk.empty()) {
        int l, r; tie(l, r) = stk.top();
        stk.pop();
        if (r - l < k) continue;

        while (r - l >= k) {
            int max_a, m; tie(max_a, m) = segtree.range_concat(l, r);
            int len_l = m - l;
            int len_r = r - m - 1;
            mint<MOD> val = a[m];
            mint<MOD> cnt = ((sum_b_size(r - l, k) - sum_b_size(len_l, k) - sum_b_size(len_r, k)) % MOD + MOD) % MOD;
            ans += val * cnt;
            stk.emplace(m + 1, r);
            r = m;
        }
    };
    return ans;
}

int main() {
    int n, k; scanf("%d%d", &n, &k);
    vector<int> a(n);
    REP (i, n) scanf("%d", &a[i]);
    auto z = solve(n, k, a);
    printf("%d\n", (int)z.data);
    return 0;
}
```
