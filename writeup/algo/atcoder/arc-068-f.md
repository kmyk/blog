---
layout: post
date: 2018-08-29T03:05:09+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "dp", "counting" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc068/tasks/arc068_d" ]
---

# AtCoder Regular Contest 068: F - Solitaire

## 解法

DP。最終的にできる列の形を整理しよう。$$O(NK)$$。

カードを追加し終わった時点では $$1$$ を中心として左右に単調な列があるので、最終的にできる列は($$1$$ より手前を見れば)単調減少な列ふたつを編み込んだものになる。
最終的にできた列からこのような単調減少な列ふたつを復元する方法は一意ではないが、片側の列ができるだけ長くかつ辞書順で大きくなるようにすれば一意になる。
よってこのような単調減少列の組の数を数えればよい。
これはARC EぐらいのDPで解ける。

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < (int)(n); ++ (i))
using namespace std;
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

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
};

constexpr int MOD = 1e9 + 7;

mint<MOD> solve(int n, int k) {
    auto dp = vectors(k + 1, n + 1, mint<MOD>());
    dp[0][0] = 1;
    REP (i, k) {
        mint<MOD> acc = 0;
        REP3 (j, 1, n + 1) {
            acc += dp[i][j - 1];
            dp[i + 1][j] += acc;  // extend the primary chain
            if (j > i and j != n) {
                dp[i + 1][j] += dp[i][j];  // extend the secondary chain
            }
        }
    }
    return dp[k][n] * (k < n ? mint<MOD>(2).pow(n - k - 1) : 1);
}

int main() {
    int n, k; cin >> n >> k;
    cout << solve(n, k).data << endl;
    return 0;
}
```
