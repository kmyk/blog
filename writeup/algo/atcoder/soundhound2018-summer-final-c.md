---
redirect_from:
  - /writeup/algo/atcoder/soundhound2018-summer-final-c/
layout: post
date: 2018-08-06T16:50:42+09:00
tags: [ "competitive", "writeup", "atcoder", "dp", "graph", "combinatorics" ]
"target_url": [ "https://beta.atcoder.jp/contests/soundhound2018-summer-final/tasks/soundhound2018_summer_final_c" ]
---

# SoundHound Programming Contest 2018 Masters Tournament 本戦: C - Not Too Close

## solution

DP。頂点$1$からの距離別にやる。組合せ等を適当に前処理して$O(N^3)$。

## note

層別にやる感じのは典型だけど頂点$1$からの距離別というのは思い付けなかった。
そこさえ分かればやるだけだけど丁寧に実装しないとだめなので頑張る。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < (int)(n); ++ (i))
#define ALL(x) begin(x), end(x)
using namespace std;
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

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
int choose_two(int n) {
    return n * (n - 1) / 2;
}

constexpr int MOD = 1e9 + 7;

int solve(int n, int d) {
    const mint<MOD> two = 2;
    mint<MOD> result = 0;
    auto dp = vectors(n, n + 1, n + 1, mint<MOD>());
    dp[0][1][1] = 1;
    REP (i, n - 1) {
        REP (j, (i + 1 >= d) ? n + 1 : n) {
            dp[i + 1][j][0] = dp[i][j][0];
            REP3 (k, 1, j) {
                REP3 (l, 1, j - k + 1) {
                    auto new_node = choose<MOD>(n - (j - k) - (i + 1 <= d), k - (i + 1 == d));
                    auto new_edge_prv = (two.pow(l) - 1).pow(k);
                    auto new_edge_cur = two.pow(choose_two(k));
                    dp[i + 1][j][k] += dp[i][j - k][l] * new_node * new_edge_prv * new_edge_cur;
                }
            }
        }
        if (i + 1 >= d) {
            REP (j, n + 1) {
                auto new_graph = two.pow(choose_two(n - j));
                result += accumulate(ALL(dp[i + 1][j]), mint<MOD>()) * new_graph;
            }
        }
    }
    return result.data;
}

int main() {
    int n, d; cin >> n >> d;
    cout << solve(n, d) << endl;
    return 0;
}
```
