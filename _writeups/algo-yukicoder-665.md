---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/665/
  - /blog/2018/03/09/yuki-665/
date: "2018-03-09T23:51:29+09:00"
tags: [ "competitive", "writeup", "yukicoder", "bernoulli-number" ]
"target_url": [ "https://yukicoder.me/problems/no/665" ]
---

# Yukicoder No.665 Bernoulli Bernoulli

## solution

ぐぐるとWikipediaが出てくる([ベルヌーイ数 # べき乗和による導入 - Wikipedia](https://ja.wikipedia.org/wiki/%E3%83%99%E3%83%AB%E3%83%8C%E3%83%BC%E3%82%A4%E6%95%B0#%E3%81%B9%E3%81%8D%E4%B9%97%E5%92%8C%E3%81%AB%E3%82%88%E3%82%8B%E5%B0%8E%E5%85%A5))のでそのようにやる。$O(K^2)$。

## note

-   まさか想定が「「ベルヌーイ数」でググってやるだけですが」とは思わなかったので必死にDPを考えていた。諦めるのが早かったためコンテスト中に解けた
-   Bernoulli数 なんだかFourier変換ぽい
-   「既出でした」としてlinkしてある [Codeforces Educational Codeforces Round 7 - F. The Sum of the k-th Powers](http://codeforces.com/contest/622/problem/F) は$k \le 10^6$なのでこのままでは通らない

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
using ll = long long;
using namespace std;

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
    if (n < r) return 0;
    return fact<MOD>(n) *(ll) inv_fact<MOD>(n - r) % MOD *(ll) inv_fact<MOD>(r) % MOD;
}

/**
 * @tparam MOD must be a prime
 * @note O(n^2)
 * @see https://ja.wikipedia.org/wiki/%E3%83%99%E3%83%AB%E3%83%8C%E3%83%BC%E3%82%A4%E6%95%B0
 */
template <int MOD>
int bernoulli_number(int i) {
    static vector<int> dp(1, 1);
    while (dp.size() <= i) {
        int n = dp.size();
        ll acc = 0;
        REP (k, n) {
            acc += choose<MOD>(n + 1, k) *(ll) dp[k] % MOD;
        }
        acc %= MOD;
        (acc *= modinv(n + 1, MOD)) %= MOD;
        acc = (acc == 0 ? 0 : MOD - acc);
        dp.push_back(acc);
    }
    return dp[i];
}

/**
 * @brief 0^k + 1^k + 2^k + ... + (n - 1)^k
 * @see https://yukicoder.me/problems/no/665
 * @note n can be >= MOD
 */
template <int MOD>
int sum_of_pow(ll n, int k) {
    ll acc = 0;
    REP (j, k + 1) {
        acc += choose<MOD>(k + 1, j) *(ll) bernoulli_number<MOD>(j) % MOD *(ll) powmod(n % MOD, k - j + 1, MOD) % MOD;
    }
    acc %= MOD;
    (acc *= modinv(k + 1, MOD)) %= MOD;
    return acc;
}


constexpr int MOD = 1e9 + 7;
int main() {
    ll n; int k; cin >> n >> k;
    int result = sum_of_pow<MOD>(n + 1, k);
    cout << result << endl;
    return 0;
}
```
