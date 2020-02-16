---
layout: post
redirect_from:
  - /blog/2018/01/03/hackerrank-hourrank-25-b/
date: "2018-01-03T11:18:31+09:00"
tags: [ "competitive", "writeup", "hackerrank", "hourrank", "palindrome" ]
"target_url": [ "https://www.hackerrank.com/contests/hourrank-25/challenges/maximum-palindromes" ]
---

# HackerRank HourRank 25: B. Maximum Palindromes

## problem

文字列$s$が与えられる。次のクエリにたくさん答えよ:

-   部分文字列$s\_{l \dots r} = s\_l s\_{l+1} \dots s\_r$が指定される。$s\_{l \dots r}$中の文字からいくつか使って並び換えて回文を作ることを考える。そのようにしてできる回文で長さが最大のものは複数ありうるが、それは何個であるか答えよ。

## solution

文字種を$L = 26$として$O((N + Q)L)$。

区間中の文字種ごとの出現の数(つまり頻度)は累積和により$O(L)$で求まる。
頻度が分かれば組み合わせ${}\_nC\_r$を使って$O(L)$で求まる。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
using ll = long long;
using namespace std;

ll powmod(ll x, ll y, ll p) {
    assert (0 <= x and x < p);
    assert (0 <= y);
    ll z = 1;
    for (ll i = 1; i <= y; i <<= 1) {
        if (y & i) z = z * x % p;
        x = x * x % p;
    }
    return z;
}
ll modinv(ll x, ll p) {
    assert (x % p != 0);
    return powmod(x, p - 2, p);
}
template <int MOD>
int fact(int n) {
    static vector<int> memo(1, 1);
    while (n >= memo.size()) {
        memo.push_back(memo.back() *(ll) memo.size() % MOD);
    }
    return memo[n];
}
template <int PRIME>
int inv_fact(int n) {
    static vector<int> memo(1, 1);
    while (n >= memo.size()) {
        memo.push_back(memo.back() *(ll) modinv(memo.size(), PRIME) % PRIME);
    }
    return memo[n];
}
template <int MOD>
int choose(int n, int r) {
    if (n < r) return 0;
    return fact<MOD>(n) *(ll) inv_fact<MOD>(n - r) % MOD *(ll) inv_fact<MOD>(r) % MOD;
}

constexpr int mod = 1e9 + 7;
int main() {
    // input
    string s; cin >> s;
    // prepare
    int n = s.length();
    vector<array<int, 26> > acc(n + 1);
    acc[0] = {};
    REP (i, n) {
        acc[i + 1] = acc[i];
        acc[i + 1][s[i] - 'a'] += 1;
    }
    // serve
    int q; cin >> q;
    while (q --) {
        int l, r; cin >> l >> r;
        -- l;
        ll result = 1;
        int even = 0;
        int odd = 0;
        REP (c, 26) {
            int cnt = acc[r][c] - acc[l][c];
            result = result * choose<mod>(even + cnt / 2, cnt / 2) % mod;
            even += cnt / 2;
            odd  += cnt % 2;
        }
        result = result * max(1, odd) % mod;
        cout << result << endl;
    }
    return 0;
}
```
