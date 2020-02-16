---
layout: post
alias: "/blog/2017/08/15/agc-009-c/"
date: "2017-08-15T15:39:24+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc", "dp", "cumulative-sum", "shakutori-method" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc009/tasks/agc009_c" ]
---

# AtCoder Grand Contest 009: C - Division into Two

蟻本などの教科書に載ってそうな感じ。

## solution

DP。
愚直だと$O(N^3)$。
$A \le B$と仮定すると$X$側の使った位置をほとんど覚えなくてよくて$O(N^2)$。
しゃくとり法と累積和で$O(N)$。

左から順に所属を決めていく。
愚直には$s\_i = \max X, \; s\_j = \max Y$であるようなときの$(X, Y)$の場合の数を$\mathrm{dp}(i, j)$とする。
$A \le B$であると仮定する。
$i \lt j - 1$であるとき$s\_i + A \le s\_{j-1} + B \le s\_j + B$であるので、$s\_{j+1}$以降の所属を決めるのに$i$の細かい値は必要ない。
$j$番目まで見たとき次に$Y$に所属させる要素$s\_k$を決めて開区間$(j, k)$の中は全て$X$に所属させるようにすると、これで$\mathrm{dp} : 2 \times (N+1) \to 10^9+7$とできて$O(N^2)$。
その更新はとりあえず書いてみて眺めれば容易に高速化でき、$O(N)$。

## implementation

`l_l > l_r`な場合で無限にWAを出した。

``` c++
#include <array>
#include <cstdio>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i, m, n) for (int i = (m); (i) < int(n); ++(i))
using ll = long long;
using namespace std;

constexpr int mod = 1e9+7;
int main() {
    // input
    int n; ll a, b; scanf("%d%lld%lld", &n, &a, &b);
    vector<ll> s(n); repeat (i, n) scanf("%lld", &s[i]);
    if (a > b) swap(a, b);
    // solve
    s.insert(s.begin(), s.front() - a - b);
    s.insert(s.end(),   s.back()  + a + b);
    s.insert(s.end(),   s.back()  + a + b);
    vector<array<int, 2> > dp(n + 2);
    vector<int> acc(dp.size() + 1);
    dp[0][0] = 1;
    acc[1] = 1;
    int l_l = 0, l_r = 0;
    repeat_from (r, 1, dp.size()) {
        while (l_r < r - 1 and s[l_r] + b <= s[r]) ++ l_r;
        if (l_l <= l_r) {
            dp[r][0] = (acc[l_r] - acc[l_l] +(ll) mod) % mod;
        }
        if (not (s[r - 1] + a <= s[r])) l_l = r - 1;
        dp[r][1] = (s[r - 1] + b <= s[r]) ? (dp[r - 1][0] + dp[r - 1][1]) % mod : 0;
        acc[r + 1] = (0ll + acc[r]
                + (s[r - 1] + a <= s[r + 1] ? dp[r][0] : 0)
                + dp[r][1] ) % mod;
    }
    // output
    int result = (dp[n + 1][0] + dp[n + 1][1]) % mod;
    printf("%d\n", result);
    return 0;
}

```
