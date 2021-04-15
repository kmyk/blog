---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc_060_c/
  - /writeup/algo/atcoder/arc-060-c/
  - /blog/2018/01/04/arc-060-c/
date: "2018-01-04T11:55:15+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "dp", "average" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc060/tasks/arc060_a" ]
---

# AtCoder Regular Contest 060: C - 高橋君とカード / Tak and Cards

editorialには$O(N \sum x\_i)$の解法があった。

## solution

DP。$i \le N$枚目までの中で$j \le N$枚選んで総和が$k \le \sum x\_i$であるような選び方の数を$\mathrm{dp}(i, j, k)$とおく。$O(N^2 \sum x\_i)$。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < int(n); ++ (i))
#define REP_R(i, n) for (int i = int(n) - 1; (i) >= 0; -- (i))
#define ALL(x) begin(x), end(x)
using ll = long long;
using namespace std;
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

int main() {
    // input
    int n, a; scanf("%d%d", &n, &a);
    vector<int> x(n); REP (i, n) scanf("%d", &x[i]);
    // solve
    int sum_x = accumulate(ALL(x), 0);
    auto dp = vectors(n + 1, sum_x + 1, ll());
    dp[0][0] = 1;
    REP (i, n) {
        REP_R (j, n) {
            REP (k, sum_x - x[i] + 1) {
                dp[j + 1][k + x[i]] += dp[j][k];
            }
        }
    }
    ll result = 0;
    REP3 (j, 1, n + 1) if (a * j <= sum_x) {
        result += dp[j][a * j];
    }
    // output
    printf("%lld\n", result);
    return 0;
}
```
