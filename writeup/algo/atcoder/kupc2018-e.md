---
layout: post
title: "Kyoto University Programming Contest 2018: E - 転倒数"
date: 2018-10-01T01:30:30+09:00
tags: [ "competitive", "writeup", "atcoder", "kupc", "inversion-number", "binary-indexed-tree", "dp", "inline-dp", "digit-dp" ]
"target_url": [ "https://beta.atcoder.jp/contests/kupc2018/tasks/kupc2018_e" ]
---

## 解法

### 概要

桁DPぽいのをして実家で加速。$O(N \log N)$。

### 詳細

長さ$i \le N$の順列全体の個数$i!$と、長さ$i \le N$の順列全体の転倒数の総和$g(i)$を求めておく。
$\lt i$桁目まで一致し$i$桁目$q \lt p_i$な場合な順列に関する転倒数の総和を$f(i)$とするとこれは$g(n - i - 1)$から求まる。
この$f(i)$の総和に$p$自身の転倒数を足せば答えになる。
このDPは素直に書けば$O(N^2)$だが、とりあえず書いてみて眺めるとbinary indexed treeで$O(N \log N)$に落ちることが分かる。

## メモ

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define REP_R(i, n) for (int i = int(n) - 1; (i) >= 0; -- (i))
using ll = long long;
using namespace std;

template <int32_t MOD>
struct mint {
    int64_t value;  // faster than int32_t a little
    mint() = default;  // value is not initialized
    mint(int64_t value_) : value(value_) {}  // assume value is in proper range
    inline mint<MOD> operator + (mint<MOD> other) const { int64_t c = this->value + other.value; return mint<MOD>(c >= MOD ? c - MOD : c); }
    inline mint<MOD> operator - (mint<MOD> other) const { int64_t c = this->value - other.value; return mint<MOD>(c <    0 ? c + MOD : c); }
    inline mint<MOD> operator * (mint<MOD> other) const { int64_t c = this->value * int64_t(other.value) % MOD; return mint<MOD>(c < 0 ? c + MOD : c); }
    inline mint<MOD> & operator += (mint<MOD> other) { this->value += other.value; if (this->value >= MOD) this->value -= MOD; return *this; }
    inline mint<MOD> & operator *= (mint<MOD> other) { this->value = this->value * int64_t(other.value) % MOD; if (this->value < 0) this->value += MOD; return *this; }
    mint<MOD> pow(uint64_t k) const {
        mint<MOD> x = *this, y = 1;
        for (; k; k >>= 1) {
            if (k & 1) y *= x;
            x *= x;
        }
        return y;
    }
    mint<MOD> inv() const { return pow(MOD - 2); }  // MOD must be a prime
    inline mint<MOD> operator / (mint<MOD> other) const { return *this * other.inv(); }
};
template <int32_t MOD> ostream & operator << (ostream & out, mint<MOD> n) { return out << n.value; }

template <int32_t MOD>
mint<MOD> fact(int n) {
    static vector<mint<MOD> > memo(1, 1);
    while (n >= memo.size()) {
        memo.push_back(memo.back() * mint<MOD>(memo.size()));
    }
    return memo[n];
}

template <typename Monoid>
struct binary_indexed_tree {  // on monoid
    typedef typename Monoid::underlying_type underlying_type;
    vector<underlying_type> data;
    Monoid mon;
    binary_indexed_tree(size_t n, Monoid const & a_mon = Monoid()) : mon(a_mon) {
        data.resize(n, mon.unit());
    }
    void point_append(size_t i, underlying_type z) {  // data[i] += z
        for (size_t j = i + 1; j <= data.size(); j += j & -j) data[j - 1] = mon.append(data[j - 1], z);
    }
    underlying_type initial_range_concat(size_t i) {  // sum [0, i)
        underlying_type acc = mon.unit();
        for (size_t j = i; 0 < j; j -= j & -j) acc = mon.append(data[j - 1], acc);
        return acc;
    }
};
struct plus_monoid {
    typedef int underlying_type;
    int unit() const { return 0; }
    int append(int a, int b) const { return a + b; }
};

ll inversion_number(vector<int> const & a) {
    int n = a.size();
    binary_indexed_tree<plus_monoid> bit(n + 1);
    ll cnt = 0;
    REP (i, n) {
        cnt += i - bit.initial_range_concat(a[i] + 1);
        bit.point_append(a[i], 1);
    }
    return cnt;
}

constexpr int MOD = 1e9 + 7;
mint<MOD> solve(int n, vector<int> const & p) {
    // count without the restriction about p
    vector<mint<MOD> > sum(n + 1);
    sum[0] = 0;
    REP (i, n) {
        auto k = mint<MOD>(i) * (i + 1) / 2;
        sum[i + 1] = sum[i] * (i + 1) + fact<MOD>(i) * k;
    }

    // count with p
    mint<MOD> acc = 0;
    mint<MOD> cnt = 0;
    binary_indexed_tree<plus_monoid> used(n);
    REP (i, n) used.point_append(i, 1);
    REP_R (i, n) {
        mint<MOD> k = p[i] - used.initial_range_concat(p[i]);

        // use q < p[i]
        acc += sum[n - i - 1] * k + fact<MOD>(n - i - 1) * (k * (k - 1) / 2);

        // use q = p[i]
        acc += cnt * k;
        cnt += fact<MOD>(n - i - 1) * k;
        used.point_append(p[i], -1);  // release
    }

    return acc + inversion_number(p) % MOD;
}

int main() {
    int n; cin >> n;
    vector<int> p(n);
    REP (i, n) {
        cin >> p[i];
        -- p[i];
    }
    cout << solve(n, p). value << endl;
    return 0;
}
```
