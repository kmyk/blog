---
layout: post
title: "AtCoder Grand Contest 025: B - RGB Coloring"
date: 2018-08-11T00:39:06+09:00
tags: [ "competitive", "writeup", "atcoder", "agc" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc025/tasks/agc025_b" ]
---

## solution

色の塗り方が直交している。
$O(N \log N)$。

$Ax + By = K$は$x \le N$を決めれば$y$も決まるのですべて試す。
色の塗り方から$1$本のタワーを$4$色で塗るのでなくて$2$本のタワーを$2$色で塗ると見做せて、$x, y$が決まると${} _ N C _ x \cdot {} _ N C _ y$通りの塗り方がある。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
using ll = long long;
using namespace std;

template <int32_t MOD>
struct mint {
    int64_t data;  // faster than int32_t a little
    mint() = default;  // data is not initialized
    mint(int64_t value) : data(value) {}  // assume value is in proper range
    inline mint<MOD> operator + (mint<MOD> other) const { int64_t c = this->data + other.data; return mint<MOD>(c >= MOD ? c - MOD : c); }
    inline mint<MOD> operator - (mint<MOD> other) const { int64_t c = this->data - other.data; return mint<MOD>(c <    0 ? c + MOD : c); }
    inline mint<MOD> operator * (mint<MOD> other) const { int64_t c = this->data * int64_t(other.data) % MOD; return mint<MOD>(c < 0 ? c + MOD : c); }
    inline mint<MOD> & operator += (mint<MOD> other) { this->data += other.data; if (this->data >= MOD) this->data -= MOD; return *this; }
    inline mint<MOD> & operator -= (mint<MOD> other) { this->data -= other.data; if (this->data <    0) this->data += MOD; return *this; }
    inline mint<MOD> & operator *= (mint<MOD> other) { this->data = this->data * int64_t(other.data) % MOD; if (this->data < 0) this->data += MOD; return *this; }
    inline mint<MOD> operator - () const { return mint<MOD>(this->data ? MOD - this->data : 0); }
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
    static vector<mint<PRIME> > memo(1, 1);
    while (n >= memo.size()) {
        memo.push_back(memo.back() * mint<PRIME>(memo.size()).inv());
    }
    return memo[n];
}
template <int32_t MOD>
mint<MOD> choose(int n, int r) {
    assert (0 <= r and r <= n);
    return fact<MOD>(n) * inv_fact<MOD>(n - r) * inv_fact<MOD>(r);
}

constexpr int MOD = 998244353;
int solve(ll n, ll a, ll b, ll k) {
    mint<MOD> cnt = 0;
    REP (x, n + 1) {
        int y = (k - a * x) / b;
        if (a * x + b * y != k) continue;
        if (not (0 <= y and y <= n)) continue;
        cnt += choose<MOD>(n, x) * choose<MOD>(n, y);
    }
    return cnt.data;
}

int main() {
    ll n, a, b, k; cin >> n >> a >> b >> k;
    cout << solve(n, a, b, k) << endl;
    return 0;
}
```
