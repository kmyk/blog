---
layout: post
redirect_from:
  - /writeup/algo/atcoder/agc_002_f/
  - /writeup/algo/atcoder/agc-002-f/
  - /blog/2018/03/13/agc-002-f/
date: "2018-03-13T22:54:25+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc", "dp", "topological-sort" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc002/tasks/agc002_f" ]
---

# AtCoder Grand Contest 002: F - Leftmost Ball

「topological sortの個数数えればいいのか綺麗だなあ」までは辿り着いたが「でも数えるのは無理なんだよな」で刈ってしまった。
一般には実際にNPよりも難しいらしい[1](http://codeforces.com/blog/entry/10911)[2](https://math.stackexchange.com/questions/814177/how-many-topological-orderings-exist-for-a-graph)。

## solution

topological sortの数を数えるDP。$O(N(N + K))$。

次の規則での並べ方を数えればよい。

-   $0$を$N$個、$1, \dots, N$をそれぞれ$K - 1$個
-   $i \in \\{ 1, \dots, N \\}$ は $i$番目(1-based)の$0$ より後ろに出現する
-   $i \in \\{ 2, \dots, N \\}$ は $1$番目の$i - 1$ より後ろに出現する

「$A$が$B$より後ろに出現する」の形の制約は、制約をDAGとして書いたグラフのtopological sortとして表現できる。
なのでこのDAGのtopological sortの数を数えればよい。
愚直に見れば$O(K^N)$かかる。
しかし$2$番目以降の$i$の出現は同じ$i$以外に対して独立なので、残りの頂点の数を$R$として${}\_{R}C\_{K-2}$を掛けることでまとめて処理できる。
これで全体で$O(2^N)$に落ちる。

## まとめ

-   「$A$が$B$より後ろに出現する」はtopological sort
-   topological sortの数を数えるのは難しいが、グラフを非連結にできれば容易

## implementation

``` c++
#include <cassert>
#include <iostream>
#include <vector>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < int(n); ++ (i))
using ll = long long;
using namespace std;
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

ll powmod(ll x, ll y, ll m) {
    assert (0 <= x and x < m);
    assert (0 <= y);
    ll z = 1;
    for (ll i = 1; i <= y; i <<= 1) {
        if (y & i) z = z * x % m;
        x = x * x % m;
    }
    return z;
}
ll modinv(ll x, ll p) {
    assert (x % p != 0);
    return powmod(x, p - 2, p);
}
template <int32_t MOD>
int32_t fact(int n) {
    static vector<int32_t> memo(1, 1);
    while (n >= memo.size()) {
        memo.push_back(memo.back() *(int64_t) memo.size() % MOD);
    }
    return memo[n];
}
template <int32_t PRIME>
int32_t inv_fact(int n) {
    static vector<int32_t> memo(1, 1);
    while (n >= memo.size()) {
        memo.push_back(memo.back() *(int64_t) modinv(memo.size(), PRIME) % PRIME);
    }
    return memo[n];
}
template <int MOD>
int choose(int n, int r) {
    assert (0 <= r and r <= n);
    return fact<MOD>(n) *(ll) inv_fact<MOD>(n - r) % MOD *(ll) inv_fact<MOD>(r) % MOD;
}

constexpr int mod = 1e9 + 7;
int solve(int n, int k) {
    if (k == 1) return 1;
    auto dp = vectors(n + 1, n + 1, int());
    dp[0][0] = 1;
    REP3 (i, 1, n + 1) {
        REP (j, i + 1) {
            if (i - 1 >= 0) {
                dp[i][j] += dp[i - 1][j];
            }
            if (j - 1 >= 0) {
                int remaining = (n - i) + (k - 1) * (n - (j - 1));
                dp[i][j] += dp[i][j - 1] *(ll) choose<mod>(remaining - 1, k - 2) % mod;
            }
            if (dp[i][j] >= mod) {
                dp[i][j] -= mod;
            }
        }
    }
    return dp[n][n] *(ll) fact<mod>(n) % mod;
}

int main() {
    int n, k; cin >> n >> k;
    cout << solve(n, k) << endl;
    return 0;
}
```
