---
redirect_from:
  - /writeup/algo/atcoder/cf18-relay-h/
layout: post
date: 2018-11-21T11:18:00+09:00
tags: [ "competitive", "writeup", "atcoder", "code-festival", "dp", "fast-mobius-transformation", "inclusion-exclusion-principle" ]
"target_url": [ "https://beta.atcoder.jp/contests/cf18-relay-open/tasks/relay2018_h" ]
---

# Code Festival (2018) Team Relay: H - 最悪のバス停決定戦

## 解法

### 概要

宣伝を行うバス停の集合$$X = \{ x_1, x_2, \dots, x_k \}$$を固定し、このようなときの目的の順列の数$$f(X)$$を数えればよい。
ただし単純に足し合わせると「宣伝はするが、宣伝をしなくてもバス停$$M$$が勝つ」ような場合に重複が発生してしまう。
しかしこれは高速Mobius変換による包除原理をすれば解決する。
$$O(N2^N)$$。

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
using namespace std;

template <int32_t MOD>
struct mint {
    int64_t value;
    mint() = default;
    mint(int64_t value_) : value(value_) {}
    inline mint<MOD> operator + (mint<MOD> other) const { int64_t c = this->value + other.value; return mint<MOD>(c >= MOD ? c - MOD : c); }
    inline mint<MOD> operator - (mint<MOD> other) const { int64_t c = this->value - other.value; return mint<MOD>(c <    0 ? c + MOD : c); }
    inline mint<MOD> operator * (mint<MOD> other) const { int64_t c = this->value * int64_t(other.value) % MOD; return mint<MOD>(c < 0 ? c + MOD : c); }
    inline mint<MOD> & operator += (mint<MOD> other) { this->value += other.value; if (this->value >= MOD) this->value -= MOD; return *this; }
    inline mint<MOD> & operator -= (mint<MOD> other) { this->value -= other.value; if (this->value <    0) this->value += MOD; return *this; }
    inline mint<MOD> & operator *= (mint<MOD> other) { this->value = this->value * int64_t(other.value) % MOD; if (this->value < 0) this->value += MOD; return *this; }
    inline mint<MOD> operator - () const { return mint<MOD>(this->value ? MOD - this->value : 0); }
    mint<MOD> pow(uint64_t k) const {
        mint<MOD> x = *this, y = 1;
        for (; k; k >>= 1) {
            if (k & 1) y *= x;
            x *= x;
        }
        return y;
    }
    mint<MOD> inv() const { return pow(MOD - 2); }  // MOD must be a prime
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

/**
 * @brief (downward) fast mobius transformation
 * @note for f : 2^n \to R; \mu f(Y) = \sum\_{X \subseteq Y} (-1)^{\|Y \setminues X\|} f(X)
 * @note O(n 2^n)
 * @note related to inclusion-exclusion principle
 * @see http://pekempey.hatenablog.com/entry/2016/10/30/205852
 * @param T is a commutative group
 */
template <typename T>
vector<T> downward_fast_mobius_transform(vector<T> f) {
    int pow_n = f.size();
    for (int i = 1; i < pow_n; i <<= 1) {
        REP (s, pow_n) {
            if (s & i) {
                f[s] -= f[s ^ i];
            }
        }
    }
    return f;
}

constexpr int MOD = 1e9 + 7;
mint<MOD> solve(int n, int m, int k) {
    int max_a = m - 1;
    int max_b = (1 << n) - m;

    vector<mint<MOD> > f(1 << n);
    REP (s, 1 << n) if (__builtin_popcount(s) <= k) {
        int c = 0;
        REP (i, n) if (s & (1 << i)) {
            c += 1 << i;
        }
        if (max_a <= c) {
            f[s] = choose<MOD>(c, max_a);
        }
    }

    auto g = downward_fast_mobius_transform(f);
    mint<MOD> acc = 0;
    REP (s, 1 << n) if (__builtin_popcount(s) <= k) {
        acc += g[s];
    }

    return acc * mint<MOD>(2).pow(n) * fact<MOD>(max_a) * fact<MOD>(max_b);
}

int main() {
    int n, m, k; cin >> n >> m >> k;
    cout << solve(n, m, k).value << endl;
    return 0;
}
```
