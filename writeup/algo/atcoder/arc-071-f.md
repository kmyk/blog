---
layout: post
alias: "/blog/2017/04/08/arc-071-f/"
date: "2017-04-08T23:10:06+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "dp" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc071/tasks/arc071_d" ]
---

# AtCoder Regular Contest 071: F - Infinite Sequence

これはみんな解いてくるよなあと思いつつだらだらやってたら落とした。誤読とか飯とかの影響とはいえ、つらい。

## solution

DP。制約を持たない列を長さごとに数える。$O(N)$。

たとえば$n = 5$であれば、$(), (1), (2, 1, 1), (3, 1, 1, 1), (4, 1, 1, 1, 1), (1, 2, 1, 1), (1, 3, 1, 1, 1), \dots$のような列はその後ろに数字を追加していくことを考えたとき、列中の数字を全て$1$と見做してよい。このようなものをまとめて数える。これはDP。

$1$以外の数が連続すると(例えば$(3, 4)$)その制約が再帰的に影響して、それ以降の数字が全て決まってしまう(同: $(3, 4, 4, 4, \dots)$)。
これと第$n$項以降は全て同じというのを合わせて、上のDP結果から計算すればよい。

## implementation

``` c++
#include <cstdio>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < int(n); ++(i))
using ll = long long;
using namespace std;
constexpr int mod = 1e9+7;
int main() {
    int n; scanf("%d", &n);
    // count free sequences
    vector<ll> dp(2*n);
    vector<ll> acc(2*n+1);
    dp[0] = 1;
    acc[1] = 1;
    repeat_from (i,1,2*n) {
        int l = max(0, i-n-1);
        int r = max(0, min(n-1, i-2));
        dp[i] = (acc[r] - acc[l] + (i-1 < n-1 ? dp[i-1] : 0)) % mod;
        acc[i+1] = (acc[i] + dp[i]) % mod;
    }
    // compute the result
    ll result = 0;
    repeat (i,n-1) {
        result += dp[i] * (n-1) % mod * (n-1) % mod;
    }
    result += dp[n-1] * n % mod;
    repeat_from (i,n,2*n) {
        result += dp[i] % mod;
    }
    result %= mod;
    if (result < 0) result += mod;
    printf("%lld\n", result);
    return 0;
}
```
