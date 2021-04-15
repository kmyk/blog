---
redirect_from:
layout: post
date: 2018-07-07T03:00:20+09:00
tags: [ "competitive", "writeup", "atcoder", "tenka1", "dp", "bit-dp" ]
"target_url": [ "https://beta.atcoder.jp/contests/tenka1-2016-final/tasks/tenka1_2016_final_d" ]
---

# 天下一プログラマーコンテスト2016本戦: D - 右往左往

## 解法

bit DPをする。移動回数は高々$N - 1$回 (典型)。依存関係の確認をbit演算でして$O(1)$に。よって$O(N^2 2^N)$。

## note

700点とあるがARC換算で400点ぐらいに見える

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < int(n); ++ (i))
using namespace std;
template <class T> inline void chmin(T & a, T const & b) { a = min(a, b); }
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

constexpr int inf = 1e9 + 7;
int main() {
    // input
    int n, m, c, d; cin >> n >> m >> c >> d;
    vector<int> a(n), b(n);
    REP (i, n) cin >> a[i] >> b[i];
    vector<int> x(m), y(m);
    REP (j, m) {
        cin >> x[j] >> y[j];
        -- x[j]; -- y[j];
    }

    // solve
    vector<int> mask(n);
    REP (j, m) {
        mask[y[j]] |= 1 << x[j];
    }

    auto dp = vectors(n, 1 << n, array<int, 2>({ inf, inf }));
    dp[0][0][0] = 0;
    dp[0][0][1] = 0;
    REP3 (s, 1, 1 << n) {
        REP (i, n) if (s & (1 << i) and (s & mask[i]) == mask[i]) {
            int t = s ^ (1 << i);
            REP (k, n) {
                REP (p, 2) {
                    chmin(dp[k][s][p], dp[k][t][p] + (p ? a[i] : b[i]));  // do i-th task
                }
            }
        }
        REP3 (k, 1, n) {
            int cost = c * (k - 1) + d;  // to move
            REP (p, 2) {
                chmin(dp[k][s][p], dp[k - 1][s][not p] + cost);
            }
        }
    }

    int ans = inf;
    REP (k, n) {
        REP (p, 2) {
            chmin(ans, dp[k][(1 << n) - 1][p]);
        }
    }

    // output
    cout << ans << endl;
    return 0;
}
```
