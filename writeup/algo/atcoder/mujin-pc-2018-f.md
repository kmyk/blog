---
layout: post
date: 2018-08-05T01:12:09+09:00
tags: [ "competitive", "writeup", "atcoder", "mujin-pc", "dp", "combinatorics" ]
"target_url": [ "https://beta.atcoder.jp/contests/mujin-pc-2018/tasks/mujin_pc_2018_f" ]
---

# Mujin Programming Challenge 2018: F - チーム分け

## solution

DP。余ってる人の数を状態に持つ。チームを大きさごとに構築する。$O(N^2 \log N)$。

「$i$番目の人まで決定して$j$チームあって $\dots$」の形だと適当に整列しても指数。
補集合を取っても簡単にはならない。
「$i$番目の人まで見て$j$人余っていて($i - j$人決定していて) $\dots$」は$a_i$の降順(つまり制約の緩い順)に整列して$O(N^3)$。
「大きさ$i$のチームまで構成して$j$人余っていて $\dots$」としてチームを作る順序を上手くやれば計算量が調和級数の和の形になって$O(N^2 \log N)$。

## note

-   まったく分からず
-   「余ってる人の数を状態に持つ」「チームを大きさごとに構築する」の$2$点が重要な発想だが、後者があれば前者も出てきやすそう

## impelementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define REP_R(i, n) for (int i = int(n) - 1; (i) >= 0; -- (i))
#define REP3R(i, m, n) for (int i = int(n) - 1; (i) >= (int)(m); -- (i))
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
template <int32_t MOD>
mint<MOD> permute(int n, int r) {
    assert (0 <= r and r <= n);
    return fact<MOD>(n) * inv_fact<MOD>(n - r);
}

constexpr int MOD = 998244353;
int solve(int n, vector<int> a) {
    vector<int> cnt(n + 1);
    for (int a_i : a) {
        cnt[a_i] += 1;
    }
    vector<mint<MOD> > cur(n + 1);
    cur[0] += 1;
    REP3R (i, 1, n + 1) {
        REP_R (j, n + 1) {
            cur[j] = j - cnt[i] >= 0 ? cur[j - cnt[i]] : 0;
        }
        auto prv = cur;
        REP (j, n + 1) {
            mint<MOD> acc = 1;
            for (int k = 0; (k + 1) * i <= j; ++ k) {
                acc *= choose<MOD>(j - k * i, i);
                cur[j - (k + 1) * i] += prv[j] * acc * permute<MOD>(k + 1, k + 1).inv();
            }
        }
    }
    return cur[0].data;
}

int main() {
    int n; cin >> n;
    vector<int> a(n);
    REP (i, n) cin >> a[i];
    cout << solve(n, a) << endl;
    return 0;
}
```
