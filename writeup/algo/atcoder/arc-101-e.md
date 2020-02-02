---
layout: post
title: "AtCoder Regular Contest 101: E - Ribbons on Tree"
date: 2018-12-07T17:24:58+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "inclusion-exclusion-principle", "tree-dp" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc101/tasks/arc101_c" ]
---

## 解法

### 概要

補集合を数える。
包除原理。
3乗ぽいけど実は2乗の木DP。
$$O(N^2)$$。

詳細は[editorial](https://img.atcoder.jp/arc101/editorial.pdf)

## メモ

-   補集合を取らずに進むと4乗ぽい木DPが出てくる。そのまま上手くやれそうだけどどうにも落ちない
-   重心分解の筋もはずれで、星型のグラフで木DPと同じ困難を抱える

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
};

constexpr int MOD = 1e9 + 7;
mint<MOD> solve(int n, vector<vector<int> > const & g) {
    // cnt[i] is the number of ways to divide the i elements into pairs
    vector<mint<MOD> > cnt(n + 3);
    cnt[0] = 1;
    for (int i = 2; i < cnt.size(); i += 2) {
        cnt[i] = cnt[i - 2] * (i - 1);
    }

    // tree dp
    function<vector<array<mint<MOD>, 2> > (int, int)> go = [&](int i, int parent) {
        vector<array<mint<MOD>, 2> > dp, dp1;
        dp.assign(2, {});
        dp[1][false] = 1;
        for (int j : g[i]) if (j != parent) {
            auto dp2 = go(j, i);
            dp.swap(dp1);
            dp.assign(dp1.size() + dp2.size() - 1, {});
            REP (t, dp1.size()) {
                REP (u, dp2.size()) {
                    REP (p, 2) {
                        REP (q, 2) {
                            dp[t][p ^ q ^ 1] += dp1[t][p] * dp2[u][q] * cnt[u];  // don't use the edge (i, j)
                            dp[t + u][p ^ q] += dp1[t][p] * dp2[u][q];  // use the edge (i, j)
                        }
                    }
                }
            }
        }
        return dp;
    };
    auto dp = go(0, -1);
    assert (dp.size() == n + 1);

    // inclusion exclusion principle
    mint<MOD> acc = 0;
    REP (i, n + 1) {
        acc += dp[i][false] * cnt[i];
        acc -= dp[i][true ] * cnt[i];
    }
    return acc;
}

int main() {
    int n; cin >> n;
    vector<vector<int> > g(n);
    REP (i, n - 1) {
        int x, y; cin >> x >> y;
        -- x; -- y;
        g[x].push_back(y);
        g[y].push_back(x);
    }
    cout << solve(n, g).value << endl;
    return 0;
}
```
