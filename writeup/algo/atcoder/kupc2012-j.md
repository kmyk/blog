---
layout: post
redirect_from:
  - /blog/2018/02/15/kupc2012-j/
date: "2018-02-15T21:19:28+09:00"
tags: [ "competitive", "writeup", "atcoder", "kupc", "dp", "monge", "knuth-yao-speedup" ]
"target_url": [ "https://beta.atcoder.jp/contests/kupc2012/tasks/kupc2012_10" ]
---

# 京都大学プログラミングコンテスト2012: J - 刺身

monge性のそれの練習のために解いた

## solution

愚直DPをKnuth-Yao speedup。$O(N^2)$。

monge性。
<https://topcoder.g.hatena.ne.jp/spaghetti_source/20120915/1347668163> の解説で十分なので、この問題について解説をすることは特にない。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < int(n); ++ (i))
#define ALL(x) begin(x), end(x)
using ll = long long;
using namespace std;
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

int main() {
    // input
    int n; cin >> n;
    vector<ll> w(n);
    REP (i, n) cin >> w[i];

    // solve
    vector<ll> acc(n + 1);
    partial_sum(ALL(w), acc.begin() + 1);
    auto dp = vectors(n + 1, n + 1, LLONG_MAX);
    auto k  = vectors(n + 1, n + 1, -1);
    REP (i, n) {
        dp[i][i + 1] = 0;
        k[i][i + 1] = i + 1;
    }
    REP3 (len, 2, n + 1) {
        REP (l, n + 1 - len) {
            ll r = l + len;
            REP3 (m, k[l][r - 1], k[l + 1][r] + 1) {
                if (dp[l][m] + dp[m][r] < dp[l][r]) {
                    dp[l][r] = dp[l][m] + dp[m][r];
                    k[l][r] = m;
                }
            }
            dp[l][r] += acc[r] - acc[l];
        }
    }

    // output
    cout << dp[0][n] << endl;
    return 0;
}
```

元となる$O(N^3)$のDP

``` c++
    ...

    // solve
    vector<ll> acc(n + 1);
    partial_sum(ALL(w), acc.begin() + 1);
    auto dp = vectors(n + 1, n + 1, LLONG_MAX);
    REP (l, n) {
        dp[l][l + 1] = 0;
    }
    REP3 (len, 2, n + 1) {
        REP (l, n + 1 - len) {
            ll r = l + len;
            REP3 (m, l + 1, r) {
                chmin(dp[l][r], dp[l][m] + dp[m][r]);
            }
            dp[l][r] += acc[r] - acc[l];
        }
    }

    ...
```
