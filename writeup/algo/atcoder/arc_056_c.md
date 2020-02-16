---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc-056-c/
  - /blog/2018/01/01/arc-056-c/
date: "2018-01-01T18:45:17+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "lie", "dp", "bit-dp", "optimization" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc056/tasks/arc056_c" ]
---

# AtCoder Regular Contest 056: C - 部門分け

## solution

DP。定数倍高速化。$O(N3^N)$。

「異なる部門に属する$2$人の間の信頼度の総和」は少し面倒なので「同じ部門に属する$2$人の信頼度の総和」を求めて結果から「信頼度の総和」を引くとする。
所属する部門が決定された人の集合を$x \subseteq N$その部門が$i \le n$個あるときの「同じ部門に属する$2$人の信頼度の総和」を$\mathrm{dp}(i, x)$とする。
集合$z$に対し$x \subseteq y \subseteq z$な組$(x, y)$はちょうど$3^{\|z\|}$個であることを踏まえればこれは$O(N3^N)$のbit-DPで求まる。

(遷移の時に毎回$K$を足すようにすれば$O(3^N)$に落ちるというのは通して解法見るまで気付きませんでした)

## implementation

``` c++
#pragma GCC optimize("O3")
#pragma GCC target("avx")
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < int(n); ++ (i))
#define REP_R(i, n) for (int i = int(n) - 1; (i) >= 0; -- (i))
using namespace std;
template <class T> inline void chmax(T & a, T const & b) { a = max(a, b); }
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

int main() {
    // input
    int n, k; scanf("%d%d", &n, &k);
    auto w = vectors(n, n, int());
    REP (y, n) REP (x, n) scanf("%d", &w[y][x]);
    // solve
    vector<int> sum_w(1 << n);
    REP3 (y, 1, 1 << n) {
        int i = __builtin_ctz(y);
        int x = y ^ (1 << i);
        sum_w[y] = sum_w[x];
        REP (j, n) if (x & (1 << j)) {
            sum_w[y] += w[i][j];
        }
    }
    int result = 0;
    vector<int> dp = sum_w;
    chmax(result, k);  // i = 1
    REP3 (i, 2, n) {
        REP_R (y, 1 << n) {
            int acc = 0;
            for (int x = y; x; x = (x - 1) & y) {  // iterate x, non-empty subsets of y, desc.
                if ((y ^ x) and x and __builtin_popcount(y ^ x) >= i - 1) {
                    chmax(acc, dp[y ^ x] + sum_w[x]);
                }
            }
            dp[y] = acc;
        }
        chmax(result, i * k + dp.back() - sum_w.back());
    }
    chmax(result, n * k - sum_w.back());  // i = n
    // output
    printf("%d\n", result);
    return 0;
}
```
