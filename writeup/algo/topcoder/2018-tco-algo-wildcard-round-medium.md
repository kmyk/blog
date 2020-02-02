---
layout: post
title: "TopCoder 2018 TCO Algorithm: Medium. Gangsters"
date: 2018-08-26T03:05:55+09:00
tags: [ "competitive", "writeup", "topcoder", "srm", "dp", "counting" ]
---

## 解法

DP。
$i$人目まで撃って$j$人生き残ることが確定して$k$人の幽霊がまだ撃ってないような状態の数を$\mathrm{dp}(i, j, k)$とおく。
$O(\mathrm{people} \cdot \mathrm{alive}^2)$。

$K = \mathrm{alive} \le N = \mathrm{people}$ と書く。
$K = 0$あるいは$2K \gt N$なら不可能。
そうでないとき、最終的な生死を `+` `-` で書いて `+----+----+-+-+-----` にようになって終わる。
この鎖 `+----` に注目してDPをする。
鎖の右端から$2$番目の人がまず最初に銃を撃ち、隣接している人が順番に銃を撃っていく。
この鎖を新たに作る / 鎖を左に伸ばす / 鎖の右端を処理する の$3$種を遷移として適切にすれば答えが求まる。

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
using namespace std;
class Gangsters { public: int countOrderings(int people, int alive); };

template <int32_t MOD>
struct mint {
    int64_t data;
    mint() = default;
    mint(int64_t value) : data(value) {}
    inline mint<MOD> operator + (mint<MOD> other) const { int64_t c = this->data + other.data; return mint<MOD>(c >= MOD ? c - MOD : c); }
    inline mint<MOD> operator * (mint<MOD> other) const { int64_t c = this->data * int64_t(other.data) % MOD; return mint<MOD>(c < 0 ? c + MOD : c); }
    inline mint<MOD> & operator += (mint<MOD> other) { this->data += other.data; if (this->data >= MOD) this->data -= MOD; return *this; }
};

constexpr int MOD = 1e9 + 7;
int Gangsters::countOrderings(int people, int alive) {
    if (alive == 0 or alive > people / 2) return 0;
    vector<vector<vector<mint<MOD> > > > dp(people + 1, vector<vector<mint<MOD> > >(alive + 1, vector<mint<MOD> >(alive + 1)));
    dp[0][0][0] = people;
    REP (i, people) {
        REP (j, alive + 1) {
            REP (k, alive + 1) {
                if (j - 1 >= 0 and k - 1 >= 0) {
                    dp[i + 1][j][k] += dp[i][j - 1][k - 1] * (j == 1 ? 1 : j - 1);  // make a new chain
                }
                if (j >= 1) {
                    dp[i + 1][j][k] += dp[i][j][k] * j;  // extend an existing chain
                }
                if (k + 1 <= alive) {
                    dp[i + 1][j][k] += dp[i][j][k + 1] * (k + 1);  // a killed person shoots
                }
            }
        }
    }
    return dp[people][alive][0].data;
}
```
