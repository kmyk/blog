---
layout: post
redirect_from:
  - /writeup/algo/hackerrank/world-codesprint-8-prime-digit-sums/
  - /blog/2016/12/20/world-codesprint-8-prime-digit-sums/
date: "2016-12-20T02:33:04+09:00"
tags: [ "competitive", "writeup", "hackerrank", "world-codesprint", "dp", "optimization" ]
"target_url": [ "https://www.hackerrank.com/contests/world-codesprint-8/challenges/prime-digit-sums" ]
---

# HackerRank World CodeSprint 8: Prime Digit Sums

## problem

整数$n$がChloe's rulesを満たすとは、その$10$進数展開の長さ$3,4,5$の(連続する)部分文字列$s$について、どのように$s$を取ってきても$\sum_i s_i$が素数になること。
桁数$n$の整数でChloe's rulesを満たすものの数を$\bmod 10^9+7$で答えよ。

## solution

DP. The function is $\mathrm{dp}: (N+1) \times 10 \times 10 \times 10 \times 10 \to \mathbb{N}$, let $\mathrm{dp}(l, a, b, c, d)$ be the number of sequences of digits which satisfies the Chloe's rules and has length $l$ and ends with $a, b, c, d$. Let $D = 10$ be the number of digits, then $O(ND^5)$. This requires to reduce the constant factor.

## implementation

The table around primes was effective.

``` c++
#include <iostream>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < int(n); ++(i))
typedef long long ll;
using namespace std;
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

// 2 3 5 7 11 13 17 19 23 29 31 37 41 43
const int is_prime[] = { false, false, true, true, false, true, false, true, false, false, false, true, false, true, false, false, false, true, false, true, false, false, false, true, false, false, false, false, false, true, false, true, false, false, false, false, false, true, false, false, false, true, false, true, false, false };
const vector<int> prime3[19] = {
    /*  0 */ { 2, 3, 5, 7, },
    /*  1 */ { 1, 2, 4, 6, },
    /*  2 */ { 0, 1, 3, 5, 9, },
    /*  2 */ { 0, 2, 4, 8, },
    /*  4 */ { 1, 3, 7, 9, },
    /*  5 */ { 0, 2, 6, 8, },
    /*  6 */ { 1, 5, 7, },
    /*  7 */ { 0, 4, 6, },
    /*  8 */ { 3, 5, 9, },
    /*  9 */ { 2, 4, 8, },
    /* 10 */ { 1, 3, 7, 9, },
    /* 11 */ { 0, 2, 6, 8, },
    /* 12 */ { 1, 5, 7, },
    /* 13 */ { 0, 4, 6, },
    /* 14 */ { 3, 5, 9, },
    /* 15 */ { 2, 4, 8, },
    /* 16 */ { 1, 3, 7, },
    /* 17 */ { 0, 2, 6, },
    /* 18 */ { 1, 5, },
};

const int max_n = 400000;
const int mod = 1e9+7;
int main() {
    vector<int> chloe(max_n+1);
    chloe[1] = 9;
    chloe[2] = 90;
    chloe[3] = 303;
    chloe[4] = 280;
    auto dp = vectors(2, 10, 10, 10, 10, ll());
    repeat (a,10) if (a != 0) {
        repeat (b,10) {
            repeat (c,10) if (is_prime[a + b + c]) {
                repeat (d,10) if (is_prime[b + c + d] and is_prime[a + b + c + d]) {
                    dp[4%2][a][b][c][d] = 1;
                }
            }
        }
    }
    repeat_from (i,4,max_n) {
        ll acc = 0;
        repeat (a,10) repeat (b,10) for (int c : prime3[a+b]) {
            for (int d : prime3[b+c]) {
                if (not dp[i&1][a][b][c][d]) continue;
                ll it = dp[i&1][a][b][c][d] % mod;
                dp[i&1][a][b][c][d] = 0;
                for (int e : prime3[c+d]) {
                    if (not is_prime[a + b + c + d + e]) continue;
                    if (not is_prime[b + c + d + e]) continue;
                    dp[(i&1)^1][b][c][d][e] += it;
                    acc += it;
                }
            }
        }
        chloe[i+1] = acc % mod;
    }
    int q; cin >> q;
    while (q --) {
        int n; cin >> n;
        cout << chloe[n] << endl;
    }
    return 0;
}
```
