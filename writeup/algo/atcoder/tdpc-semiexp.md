---
layout: post
alias: "/blog/2015/10/05/tdpc-semiexp/"
title: "Typical DP Contest F - 準急"
date: 2015-10-05T22:44:24+09:00
tags: [ "atcoder", "competitive", "writeup", "dp", "typical-dp-contest" ]
---

半日かかった。dp苦手すぎる。

<!-- more -->

## [F - 準急](https://beta.atcoder.jp/contests/tdpc/tasks/tdpc_semiexp) {#f}

### 問題

N個の駅のある路線を準急が走る。以下の条件を満たす停車駅の組み合わせの数を求めよ。

-   1個目、N個目の駅に止まる。
-   連続してK個の駅に止まることはない。

### 解法

まず、最後に`i`番目の駅に停車しそれが連続停車`j`駅目であるような停車駅の組み合わせ`dp[i][j]`を計算することを考える。
`i-2`駅目かそれ以前の駅に最後に止まる組み合わせ全ての数が`dp[i][1]`であり、`j >= 2`に関しては`dp[i][j] = dp[i-1][j-1]`である。

単純にすると$O(N^2K)$と間に合わない。
`dp[i][1]`を計算する部分で累積和を用い、`dp[i][1] = acc[i-2]`とすると$O(NK)$。
`dp[i][j] = dp[i-1][j-1] = ... = dp[i-j+1][1] = acc[i-j-1]`であることを用いて、dp tableから連続で何駅停車したかの情報を落とせば$O(N)$。ただし負の引数の`acc`が何を表すために用いられているかに注意。

### 実装

#### $O(n)$解

``` c++
#include <iostream>
#include <vector>
#include <cassert>
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define repeat(i,n) repeat_from(i,0,n)
typedef long long ll;
using namespace std;
constexpr ll mod = 1000000007;
int main() {
    int n, k; cin >> n >> k;
    vector<ll> dp(n);
    vector<ll> acc(n);
    dp[0] = 1;
    acc[0] = 1;
    repeat_from (x,1,n) {
        ll ex = x-k+1 == 0 ? 1 : 0 <= x-k-1 ? acc[x-k-1] : 0;
        dp[x] = (acc[x-1] - ex + mod) % mod;
        acc[x] = (acc[x-1] + dp[x]) % mod;
    }
    cout << dp[n-1] << endl;
    return 0;
}
```

#### $O(n^2k)$解

直接実装するだけの能力がないので、確実に正しい答えを返すものを少しずつ修正していった。その過程でできたもの。

``` c++
#include <iostream>
#include <vector>
#include <cassert>
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define repeat(i,n) repeat_from(i,0,n)
typedef long long ll;
using namespace std;
constexpr ll mod = 1000000007;
int main() {
    int n, k; cin >> n >> k;
    vector<vector<ll> > dp(n, vector<ll>(k-1));
    dp[0][0] = 1;
    repeat_from (x,1,n) {
        repeat (y,x-1) {
            repeat (z,k-1) {
                dp[x][0] += dp[y][z];
                dp[x][0] %= mod;
            }
        }
        repeat_from (y,1,k-1) {
            dp[x][y] += dp[x-1][y-1];
            dp[x][y] %= mod;
        }
    }
    ll result = 0;
    repeat (x,k-1) {
        result += dp[n-1][x];
        result %= mod;
    }
    cout << result << endl;
    return 0;
}
```
