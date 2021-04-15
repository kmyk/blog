---
layout: post
redirect_from:
  - /writeup/algo/codeforces/908-e/
  - /blog/2017/12/30/cf-908-e/
date: "2017-12-30T12:48:33+09:00"
tags: [ "competitive", "writeup", "codeforces", "sigma-aldgebra", "boolean-aldgebra", "bell-number", "combinatorics" ]
"target_url": [ "http://codeforces.com/contest/908/problem/E" ]
---

# Codeforces Good Bye 2017: E. New Year and Entity Enumeration

コンテスト終了後に$\sigma$加法族ってみんな言ってたけれど、この$\sigma$とはcountableを指すのにそもそもが有限なのでなんだか気持ち悪い。
少なくとも問題文中のstatementsそのものは有限加法性しか言っておらず、また考察を進めれば有限Boole代数であることまで言えるはず。

## problem

$m \le 1000$と$T \subseteq \mathcal{P}(M)$が与えられる。$M = 2^m - 1$とする。次を満たす$S$の数を$\bmod 10^9 + 7$で答えよ。

1.  $\forall a \in S. a \; \mathrm{XOR} \; M \in S$
2.  $\forall a, b \in S. a \; \mathrm{AND} \; b \in S$
3.  $T \subseteq S$
4.  $\forall a \in S. a \le M$

## solution

$S$は有限Boole代数。atomのそれぞれについてpopcountを数えてBell数。$O(m^2 + mn)$。

Boole代数になることについて。これは次ができるため。

-   bit積 $x \wedge y = x \; \mathrm{AND} \; y$
-   bit反転 $x^C = x \; \mathrm{XOR} \; M$
-   bit和 $x \vee y = (x^C \wedge y^C)^C$

$i \lt m$に対し$T$の要素あるいはその補元で$i$-bit目が$1$であるもの全てのbit積を$f(i)$とする。
$A = \\{ f(i) \mid i \lt m \\}$とすれば、これは$T$から生成されるBoole代数のatomの全体となる。
$A$の要素は互いに素でそのbit和は$M$であることが言える。
違うatomに属するbitは独立である。

同じatom内では、元を追加して細かいatomに分ける操作が考えられる。
atomのpopcountを$a$とするとこれを砕いてできうるatomの組の数は、$a$個の区別されたものを好きな数の(順序を持たない)グループに分割する数と同じ。
これはBell数と呼ばれるもので、$O(m^2)$で求まる。

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
template <int MOD>
int inv_fact(int n) {
    static vector<int> memo(1, 1);
    while (n >= memo.size()) {
        memo.push_back(memo.back() *(ll) modinv(memo.size(), MOD) % MOD);
    }
    return memo[n];
}
template <int MOD>
int choose(int n, int r) {
    if (n < r) return 0;
    return fact<MOD>(n) *(ll) inv_fact<MOD>(n - r) % MOD *(ll) inv_fact<MOD>(r) % MOD;
}

template <int MOD>
int bell_number(int n) {
    vector<int> dp(n + 1);
    dp[0] = 1;
    REP (i, n) {
        ll acc = 0;
        REP (j, i + 1) {
            acc += dp[j] *(ll) choose<MOD>(i, j) % MOD;
        }
        dp[i + 1] = acc % MOD;
    }
    return dp[n];
}

constexpr ll mod = 1e9 + 7;
int main() {
    // input
    int m, n; scanf("%d%d", &m, &n);
    assert (m <= 1000);
    vector<bitset<1000> > t(n);
    REP (y, n) {
        REP (x, m) {
            char c; scanf(" %c", &c);
            t[y][x] = (c != '0');
        }
    }
    // solve
    bitset<1000> mask = (bitset<1000>().flip() << m).flip();
    unordered_set<bitset<1000> > atoms;
    REP (x, m) {
        bitset<1000> acc = mask;
        REP (y, n) {
            acc &= t[y][x] ? t[y] : (~ t[y]);
        }
        atoms.insert(acc);
    }
    ll result = 1;
    for (auto atom : atoms) {
        result *= bell_number<mod>(atom.count());
        result %= mod;
    }
    // output
    printf("%lld\n", result);
    return 0;
}
```
