---
layout: post
date: 2018-09-14T02:12:54+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "frontier-dp", "dp", "counting" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc020/tasks/arc020_4" ]
---

# AtCoder Regular Contest 020: D - お菓子の国の旅行

## 解法

frontier法っぽいDPをやるだけ。
$O(NMK^2)$。

左から順に$i \le N$番目まで見て、まだ閉じられていない「く」の字の形の鎖が$j \le K$個あり、ここまで全体で$k \le K$個使っていて、ここまでの距離の総和が$l \in \mathbb{Z}/M\mathbb{Z}$で、始点がもう決まったかどうか$m \in 2$、終点がもう決まったかどうか$n \in 2$、これらに対しそのような状態の個数を$\mathrm{dp}(i, j, k, l, m, n) \in \mathbb{F} _ {10^9 + 7}$として数える。

## メモ

-   遷移の数が13個の6次元DPつらすぎた
-   想定解は$O(NMK 2^K)$だった
-   参考: [競技プログラミングにおける連結DP問題まとめ - はまやんはまやんはまやん](https://www.hamayanhamayan.com/entry/2017/10/04/113042)

## 実装

``` c++
#include <array>
#include <iostream>
#include <vector>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
using ll = long long;
using namespace std;
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

/**
 * in terminal: *--->
 *
 * out terminal: *---<
 *
 *            ,---<
 * left loop: *
 *            `--->
 *
 *             <---,
 * right loop:     *
 *             >---`
 */

constexpr int MOD = 1e9 + 7;
ll solve(int n, int m, int k, vector<int> const & d) {
    ll answer = 0;
    constexpr int   NONE = 0;
    constexpr int OPENED = 1;
    constexpr int CLOSED = 2;
    auto dp = vectors(n, k + 1, k + 1, m, array<array<ll, 3>, 3>());

    REP (i, n - 1) {
        dp[i][0][1][0][OPENED][  NONE] += 1;  // new in-terminal
        dp[i][0][1][0][  NONE][OPENED] += 1;  // new out-terminal
        dp[i][1][1][0][  NONE][  NONE] += 1;  // new left-loop
        REP (loop, k) REP (visited, k) REP (dist, m) REP (in, 3) REP (out, 3) {
            if (in == CLOSED and out == CLOSED) continue;
            ll it = (dp[i][loop][visited][dist][in][out] %= MOD);
            int cnt = 2 * loop + (in == OPENED) + (out == OPENED);
            auto ndist = (dist + cnt * d[i]) % m;
            dp[i + 1][loop][visited    ][ndist][in][out] += it;  // dosn't use the (i + 1)-th shop
            dp[i + 1][loop][visited + 1][ndist][in][out] += cnt * it;  // use the (i + 1)-th shop through
            dp[i + 1][loop + 1][visited + 1][ndist][in][out] += it;  // add left-loop
            if (2 <= loop) {
                dp[i + 1][loop - 1][visited + 1][ndist][in][out] += loop * (loop - 1) * it;  // connect two left-loops using a right-loop
            }
            if (1 <= loop and in == OPENED) {
                dp[i + 1][loop - 1][visited + 1][ndist][in][out] += loop * it;  // extend in-terminal with left- and right- loops
            }
            if (1 <= loop and out == OPENED) {
                dp[i + 1][loop - 1][visited + 1][ndist][in][out] += loop * it;  // extend out-terminal with left- and right- loops
            }
            if (in == NONE) {
                dp[i + 1][loop][visited + 1][ndist][OPENED][out] += it;  // add in-terminal *--->
            }
            if (in == NONE and loop >= 1) {
                dp[i + 1][loop - 1][visited + 1][ndist][OPENED][out] += loop * it;  // connect with in-terminal <---*
            }
            if (out == NONE) {
                dp[i + 1][loop][visited + 1][ndist][in][OPENED] += it;  // add out-terminal *---<
            }
            if (out == NONE and loop >= 1) {
                dp[i + 1][loop - 1][visited + 1][ndist][in][OPENED] += loop * it;  // connect in-terminal >---*
            }
            if (in == OPENED and out == NONE) {
                dp[i + 1][loop][visited + 1][ndist][CLOSED][CLOSED] += it;  // close with new out-terminal
            }
            if (in == NONE and out == OPENED) {
                dp[i + 1][loop][visited + 1][ndist][CLOSED][CLOSED] += it;  // close with new in-terminal
            }
            if (in == OPENED and out == OPENED) {
                dp[i + 1][loop][visited + 1][ndist][CLOSED][CLOSED] += it;  // close in- and out- terminal using a right-loop
            }
        }
        answer += dp[i + 1][0][k][0][CLOSED][CLOSED] % MOD;
    }

    return answer % MOD;
}

int main() {
    int n, m, k; cin >> n >> m >> k;
    vector<int> d(n - 1);
    REP (i, n - 1) cin >> d[i];
    cout << solve(n, m, k, d)<< endl;
    return 0;
}
```
