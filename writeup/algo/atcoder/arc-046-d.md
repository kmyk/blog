---
layout: post
title: "AtCoder Regular Contest 046: D - うさぎとマス目"
date: 2018-09-04T06:03:41+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "gcd" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc046/tasks/arc046_d" ]
---

## 解法

パズル。
$1$箇所決めれば再帰的に$n$箇所決まる(典型)。
その決まり方をよく見れば周期性があり、あとは適当にすれば求まる。
$O(H + W)$。

詳細はeditorial見て。

## メモ

なぜこれが思い付かなかったのか。

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
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
    mint<MOD> pow(uint64_t k) const {
        mint<MOD> x = *this;
        mint<MOD> y = 1;
        for (uint64_t i = 1; i and (i <= k); i <<= 1) {
            if (k & i) y *= x;
            x *= x;
        }
        return y;
    }
    mint<MOD> inv() const {
        return pow(MOD - 2);
    }
};

template <int32_t MOD>
mint<MOD> fact(int n) {
    static vector<mint<MOD> > memo(1, 1);
    while (n >= memo.size()) {
        memo.push_back(memo.back() * mint<MOD>(memo.size()));
    }
    return memo[n];
}
template <int32_t PRIME>
mint<PRIME> inv_fact(int n) {
    static vector<mint<PRIME> > memo;
    if (memo.size() <= n) {
        int l = memo.size();
        int r = n * 1.3 + 100;
        memo.resize(r);
        memo[r - 1] = fact<PRIME>(r - 1).inv();
        for (int i = r - 2; i >= l; -- i) {
            memo[i] = memo[i + 1] * (i + 1);
        }
    }
    return memo[n];
}

template <int32_t MOD>
mint<MOD> choose(int n, int r) {
    assert (0 <= r and r <= n);
    return fact<MOD>(n) * inv_fact<MOD>(n - r) * inv_fact<MOD>(r);
}

ll lcm(int a, int b) {
    return (ll)a * b / __gcd(a, b);
}

constexpr int MOD = 1e9 + 7;
mint<MOD> solve(int h, int w) {
    int d = __gcd(h, w);
    mint<MOD> cnt = 0;
    REP (y, d + 1) {
        int x = d - y;
        if (not y or not x) continue;
        int hk = h / __gcd(h, y);
        int wk = w / __gcd(w, x);
        if (y and x and lcm(hk, wk) * d == (ll)h * w) {
            cnt += choose<MOD>(x + y, y);
        }
    }
    return cnt;
}

int main() {
    int h, w; cin >> h >> w;
    cout << solve(h, w).data << endl;
    return 0;
}
```
