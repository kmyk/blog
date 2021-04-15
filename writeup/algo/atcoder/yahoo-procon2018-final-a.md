---
layout: post
redirect_from:
  - /writeup/algo/atcoder/yahoo-procon2018-final-a/
  - /blog/2018/03/01/yahoo-procon2018-final-a/
date: "2018-03-01T08:24:44+09:00"
tags: [ "competitive", "writeup", "atcoder", "yahoo-procon", "gcd", "prime-number", "sieve-of-eratosthenes", "inclusion-exclusion-principle", "imos-method" ]
"target_url": [ "https://beta.atcoder.jp/contests/yahoo-procon2018-final-open/tasks/yahoo_procon2018_final_a" ]
---

# 「みんなのプロコン 2018」決勝: A - Uncommon

## solution

Eratosthenesの篩と包除原理で上手くやる。配る感じにしてimos法っぽく。
計算量はよく分からない。
とりあえずは$K = \max \\{ M, \max a\_i \\}$として$O(\sum\_i f(\max a\_i) + K \log \log K)$。
ただし$f(n)$は$n$の素因数の種類の数の指数で、例えば$n = 60 = 2^2 \cdot 3 \cdot 5$なら素因数の種類の数$d = \\# \\{ 2, 3, 5 \\} = 3$なので$f(n) = 2^d = 8$。

$i = 1, 2, \dots, M$についてとりあえず答えを$N$としておき、$a\_i$を順に見てここから引いていく。
まず$10^5$までの各数を素因数分解する。
これはEratosthenesの篩を利用して$O(K \log \log K)$。
各$a\_i$についてその素因数集合の部分集合を$f(a\_i)$個全て列挙し、その大きさに応じて答えの列から$\pm 1$をいい感じに引いていく。
引いていく部分を愚直にやると間に合わないので、実際には差分の配列に記録しておいて最後にimos法のようにまとめてやる。

## note

$N, M, a\_i \le 10^5$と作用する側とされる側の大きさが同じで対称な感じがあることに気付いて、$a\_i$を配る方向を試せば解ける。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < int(n); ++ (i))
#define ALL(x) begin(x), end(x)
using namespace std;

int main() {
    // input
    int n, m; scanf("%d%d", &n, &m);
    vector<int> a(n); REP (i, n) scanf("%d", &a[i]);

    // solve
    int limit = max(m, *max_element(ALL(a))) + 1;
    vector<vector<int> > prime_factors(limit);
    REP3 (p, 2, limit) if (prime_factors[p].empty()) {
        for (int x = p; x < limit; x += p) {
            prime_factors[x].push_back(p);
        }
    }
    vector<int> coeff(limit);
    for (int a_i : a) {
        int size = prime_factors[a_i].size();
        REP3 (s, 1, 1 << size) {
            int q = 1;
            REP (j, size) if (s & (1 << j)) {
                q *= prime_factors[a_i][j];
            }
            int sign = __builtin_popcount(s) % 2 == 1 ? + 1 : - 1;
            coeff[q] += sign;
        }
    }
    vector<int> result(m + 1, n);
    REP (q, m + 1) if (coeff[q]) {
        for (int x = q; x <= m; x += q) {
            result[x] -= coeff[q];
        }
    }

    // output
    REP3 (x, 1, m + 1) {
        printf("%d\n", result[x]);
    }
    return 0;
}
```
