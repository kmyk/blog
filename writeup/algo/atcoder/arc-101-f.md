---
layout: post
date: 2018-09-27T03:46:08+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "dp", "inline-dp", "segment-tree" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc101/tasks/arc101_d" ]
---

# AtCoder Regular Contest 101: F - Robots and Exits

## 解法

### 概要

区間をソートして順番に決めていくやつ (典型)。
よく見ると実家DP (典型)。
$O(N \log N + M)$。

### 詳細

ロボットは左右の最も近い出口からしか出ない。
それぞれについて右から出るか左から出るかを決めていけばよい。

ロボットは一様に動く。
これにより左右の出口との距離のみを持てばよく、特に他のロボットのそれとの大小のみ気にすればよい。
なお左に出口がないあるいは右に出口がないロボットがありうるが、それらは出る出口が一意なために無視してしまってよい。

ロボット$i$に対するそのような左右の出口との距離をそれぞれ$l_i, r_i$とおく。
このとき次のふたつが分かる:

-   $l_j \le l_i$ かつ $r_i \le r_j$ であってロボット$i$が左の出口から出るなら、ロボット$j$も左の出口から出なくてはならない
-   $l_i \le l_j$ かつ $r_j \le r_i$ であってロボット$i$が右の出口から出るなら、ロボット$j$も右の出口から出なくてはならない

さてロボットを$l_i$の昇順に並べよう。
さらに簡単のため$l_i$はすべて相異なると(一旦は)仮定しよう。
するとロボットの左右を添字$i$の順に決めてきたとき、次が言える。

-   過去に右に出ると決めたロボット $j \lt i$ であって $r_i \le r_j$ なものがあるなら、ロボット$i$は左の出口からは出てはいけない

これは右に出ると決めたロボット $j$ の $r_j$ の最大値だけ覚えておけばよい。
これで$O(N^2)$のDPになる。

さらに簡単のため$l_i$はすべて相異なると仮定していたが、これは無視できない。
制約は次のような形で効く:

-   $l_i = l_j$ かつ $r_i \le r_j$ であってロボット$i$が左の出口から出るなら、ロボット$j$も左の出口から出なくてはならない

これは同じ$l_i$の値を持つロボットをまとめて、$r_i$の小さい順にどこまでが右でどこからが左かを分けるようにするなどすればよい。
やはり$O(N^2)$である。

ここで実家DPに落ちるのだろうという雰囲気を感じとりとりあえずコードに落とし、その実装をよく長めると$O(N \log N)$になる。

## メモ

-   典型なのに4時間かかった。まあ自力なのでよし
-   editorial簡潔すぎないか、特に英語版ひどいぞ

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define REP_R(i, n) for (int i = int(n) - 1; (i) >= 0; -- (i))
#define ALL(x) begin(x), end(x)
using namespace std;
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

template <int32_t MOD>
struct mint {
    int64_t value;  // faster than int32_t a little
    mint() = default;  // value is not initialized
    mint(int64_t value_) : value(value_) {}  // assume value is in proper range
    inline mint<MOD> operator + (mint<MOD> other) const { int64_t c = this->value + other.value; return mint<MOD>(c >= MOD ? c - MOD : c); }
    inline mint<MOD> operator - (mint<MOD> other) const { int64_t c = this->value - other.value; return mint<MOD>(c <    0 ? c + MOD : c); }
    inline mint<MOD> operator * (mint<MOD> other) const { int64_t c = this->value * int64_t(other.value) % MOD; return mint<MOD>(c < 0 ? c + MOD : c); }
    inline mint<MOD> & operator += (mint<MOD> other) { this->value += other.value; if (this->value >= MOD) this->value -= MOD; return *this; }
    inline mint<MOD> & operator -= (mint<MOD> other) { this->value -= other.value; if (this->value <    0) this->value += MOD; return *this; }
    inline mint<MOD> & operator *= (mint<MOD> other) { this->value = this->value * int64_t(other.value) % MOD; if (this->value < 0) this->value += MOD; return *this; }
};
template <int32_t MOD> ostream & operator << (ostream & out, mint<MOD> n) { return out << n.value; }

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

template <int32_t MOD>
struct plus_monoid {
    typedef mint<MOD> underlying_type;
    underlying_type unit() const { return 0; }
    underlying_type append(underlying_type a, underlying_type b) const { return a + b; }
};

constexpr int MOD = 1e9 + 7;

mint<MOD> solve(int n, int m, vector<int> const & robots, vector<int> const & exits) {
    map<int, vector<int> > ranges;
    {  // with two-pointers
        int i = 0;
        while (i < n and robots[i] < exits[0]) ++ i;  // they must go right
        int j = 0;
        for (; i < n; ++ i) {
            while (j + 1 < m and exits[j + 1] < robots[i]) ++ j;
            if (j + 1 == m) break;  // they must go left
            int l = robots[i] - exits[j];
            int r = exits[j + 1] - robots[i];
            ranges[l].push_back(r);
        }
    }

    // coordinates compression
    map<int, int> rights;
    rights[0] = -1;
    for (auto const & range : ranges) {
        auto const & rs = range.second;
        for (int r : rs) {
            rights[r] = -1;
        }
    }
    {
        int size = 0;
        for (auto & it : rights) {
            it.second = size;
            ++ size;
        }
    }
    for (auto & range : ranges) {
        auto & rs = range.second;
        sort(ALL(rs));
        rs.erase(unique(ALL(rs)), rs.end());
        for (int & r : rs) {
            r = rights[r];
        }
    }

    // inline dp
    segment_tree<plus_monoid<MOD> > dp(rights.size());
    dp.point_set(0, 1);
    for (auto const & range : ranges) {
        auto const & rs = range.second;
        REP_R (i, rs.size() + 1) {
            int r = (i - 1 >= 0 ? rs[i - 1] : 0);
            dp.point_set(r, dp.range_concat(0, r + 1));
        }
    }

    return dp.range_concat(0, rights.size());
}

int main() {
    int n, m; cin >> n >> m;
    vector<int> x(n);
    REP (i, n) cin >> x[i];
    vector<int> y(m);
    REP (j, m) cin >> y[j];
    cout << solve(n, m, x, y).value << endl;
    return 0;
}
```
