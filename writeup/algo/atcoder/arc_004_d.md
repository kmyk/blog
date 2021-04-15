---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc_004_d/
  - /writeup/algo/atcoder/arc-004-d/
  - /blog/2015/09/28/arc-004-d/
date: 2015-09-28T21:04:17+09:00
tags: [ "competitive", "atcoder", "arc", "writeup" ]
---

# AtCoder Regular Contest 004 D - 表現の自由 ( Freedom of expression )

毎日blogを更新する(== 1日1問解く)の習慣になってきた

<!-- more -->

## [D - 表現の自由 ( Freedom of expression )](https://beta.atcoder.jp/contests/arc004/tasks/arc004_4) {#d}

あまり難しくない

## 解法

素因数分解して巾乗で表記したときの指数のそれぞれについて分けて考える。その数をm個に配る配り方の数を計算する。
負符号については、2乗すると1になってしまうので素数と同様には扱えず、可能な負符号の数すべてについて、m個からその数だけ選ぶ選び方の数を計算し和をとる。
これらすべての積をとれば答え。

$N \le 10^9$であるが、その素因数分解したときの指数であるので$\log$が掛かるので特に問題なく計算できる。
組合せの数は$M \le 10^5$で$M/2$回ほど呼び出されるが、前処理しておけば問題ない。

## 解答

``` c++
#include <iostream>
#include <vector>
#include <map>
#include <algorithm>
#include <cassert>
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define repeat(i,n) repeat_from(i,0,n)
typedef long long ll;
using namespace std;
ll inv(ll x, ll p) {
    assert (0 < x and x < p);
    ll y = 1;
    for (int i = 0; (1 << i) <= p - 2; ++ i) {
        if ((p - 2) & (1 << i)) {
            y = y * x % p;
        }
        x = x * x % p;
    }
    return y;
}
constexpr ll mod = 1000000007;
ll combination(ll n, ll r) {
    static vector<ll> fact(1,1);
    static vector<ll> ifact(1,1);
    if (not (n < int(fact.size()))) {
        int l = fact.size();
        fact.resize(n + 1);
        ifact.resize(n + 1);
        for (int i = l; i < n + 1; ++ i) {
            fact[i] = fact[i-1] * i % mod;
            ifact[i] = inv(fact[i], mod);
        }
    }
    r = min(r, n - r);
    return fact[n] * ifact[n-r] % mod * ifact[r] % mod;
}
map<ll,int> prime_factors(ll n) {
    map<ll,int> result;
    ll a = 2;
    while (a*a <= n) {
        if (n % a == 0) {
            result[a] += 1;
            n /= a;
        } else {
            a += 1;
        }
    }
    if (n != 1) result[n] += 1;
    return result;
}
ll distribution(ll n, ll m) { // the number of ways to distribute n things to m-elements sequence
    vector<vector<ll> > dp(m+1, vector<ll>(n+1));
    dp[0][n] = 1;
    repeat_from (i,1,m+1) {
        repeat (j,n+1) {
            for (int k = 0; j+k < n+1; ++ k) {
                dp[i][j] = (dp[i][j] + dp[i-1][j+k]) % mod;
            }
        }
    }
    return dp[m][0];
}
int main() {
    ll n, m; cin >> n >> m;
    ll result = 0;
    repeat (i,m+1) {
        if (i % 2 == (n >= 0 ? 0 : 1)) {
            result = (result + combination(m, i)) % mod;
        }
    }
    for (auto p : prime_factors(abs(n))) {
        result = result * distribution(p.second, m) % mod;
    }
    cout << result << endl;
    return 0;
}
```

`distribution`以外のすべて(`inv` `combination` `prime_factors`)はライブラリぺたりしただけ
