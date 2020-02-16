---
layout: post
date: 2018-11-21T11:12:35+09:00
tags: [ "competitive", "writeup", "atcoder", "code-festival", "linearity" ]
"target_url": [ "https://beta.atcoder.jp/contests/cf18-relay-open/tasks/relay2018_e" ]
---

# Code Festival (2018) Team Relay: E - 狼と狐

## 解法

### 概要

数え上げ順序の入れ替え。
隣接する椅子の組ごとに独立に数えればよい。
$$O(|S|)$$。

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define ALL(x) begin(x), end(x)
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

constexpr int MOD = 1e9 + 7;
mint<MOD> solve(string const & s, int a) {
    int x = a - count(ALL(s), 'W');
    int y = s.length() - a - count(ALL(s), 'F');
    assert (x + y == count(ALL(s), '?'));
    mint<MOD> acc = 0;
    REP (i, s.length()) {
        char c = s[i];
        char d = s[(i + 1) % s.length()];
        if ((c == 'W' and d == 'F') or (c == 'F' and d == 'W')) {
            acc += choose<MOD>(x + y, x);
        } else if ((c == 'W' and d == '?') or (c == '?' and d == 'W')) {
            if (y >= 1) {
                acc += choose<MOD>(x + y - 1, x);
            }
        } else if ((c == 'F' and d == '?') or (c == '?' and d == 'F')) {
            if (x >= 1) {
                acc += choose<MOD>(x - 1 + y, x - 1);
            }
        } else if (c == '?' and d == '?') {
            if (x >= 1 and y >= 1) {
                acc += choose<MOD>(x - 1 + y - 1, x - 1) * 2;
            }
        } else {
            assert (c == d);
        }
    }
    return acc;
}

int main() {
    string s; cin >> s;
    int a; cin >> a;
    cout << solve(s, a).value << endl;
    return 0;
}
```
