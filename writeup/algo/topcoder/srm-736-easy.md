---
redirect_from:
  - /writeup/algo/topcoder/srm-736-easy/
layout: post
date: 2018-08-16T02:18:40+09:00
tags: [ "competitive", "writeup", "topcoder", "srm", "modulo" ]
---

# TopCoder SRM 736 Div1 Easy: DigitRotation

## solution

$O(n^3)$ で愚直に全部試す。
手を抜いて $O(n^3 \log n)$ だとおそらく落ちる。

## note

ところで 30% rule 厳しすぎではないか。
空行以外のどの行を消してもコンパイル通らないはずなのに怒られるの理不尽すぎる。

## implementation

最大ケースでも手元$0.3$秒

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
using namespace std;
class DigitRotation { public: int sumRotations(string x); };

template <int32_t MOD>
struct mint {
    int64_t data;  // faster than int32_t a little
    mint() = default;  // data is not initialized
    mint(int64_t value) : data(value) {}  // assume value is in proper range
    inline mint<MOD> operator + (mint<MOD> other) const { int64_t c = this->data + other.data; return mint<MOD>(c >= MOD ? c - MOD : c); }
    inline mint<MOD> operator - (mint<MOD> other) const { int64_t c = this->data - other.data; return mint<MOD>(c <    0 ? c + MOD : c); }
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
};

constexpr int MOD = 998244353;
int DigitRotation::sumRotations(string x) {
    // prepare
    int n = x.length();
    vector<mint<MOD> > e(n);
    mint<MOD> x1 = 0;
    REP (i, n) {
        e[i] = mint<MOD>(10).pow(n - i - 1);
        x1 += mint<MOD>(x[i] - '0') * e[i];
    }

    // sum
    mint<MOD> sum = 0;
    auto f = [&](char c, int i) { return mint<MOD>(c - '0') * e[i]; };
    REP (c, n) REP (b, c) REP (a, b) {
        if (a == 0 and x[c] == '0') continue;
        sum += x1
            - f(x[a], a) - f(x[b], b) - f(x[c], c)
            + f(x[c], a) + f(x[a], b) + f(x[b], c);
    }
    return sum.data;
}
```
