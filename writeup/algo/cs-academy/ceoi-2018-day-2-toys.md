---
layout: post
date: 2018-08-17T03:49:03+09:00
tags: [ "competitive", "writeup", "csacademy", "dp", "prime-factors" ]
"target_url": [ "https://csacademy.com/contest/ceoi-2018-day-2/task/toys-small/", "https://csacademy.com/contest/ceoi-2018-day-2/task/toys-big/" ]
---

# CS Academy CEOI 2018 Day 2: Toys Small / Toys Big

## problem

$n \le 10^9$ に対し集合 $$\left\{ \sum a_i \mid a \text{は自然数の有限列}, \prod (a_i + 1) = n \right\}$$ を答えよ。

## solution

$\mathrm{dp} : \mathbb{N} \to \mathcal{P}(\mathbb{N})$ を目的の集合を求める関数とする。
これを動的計画法で計算。
答えの大きさを $r$ として $O(d(n)^2r)$ で通る。

$n \le 10^9$ と大きいが $\mathrm{dp}(n)$ を計算するには $n$の約数$d$についてだけ$\mathrm{dp}(d)$を計算すればよい。
$n \le 10^9$ のときその約数の個数 $d(n) \le 1200 + a$ であるので十分小さい。
答えの大きさ $r$ が効いてくるのが不安だが、なぜか通る。

## note

これ通ってしまうの想定されてなかったりしそう

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < (int)(n); ++ (i))
#define ALL(x) begin(x), end(x)
using ll = long long;
using namespace std;

vector<int> list_primes(int n) {
    vector<bool> is_prime(n, true);
    is_prime[0] = is_prime[1] = false;
    for (int i = 2; i *(ll) i < n; ++ i)
        if (is_prime[i])
            for (int k = 2 * i; k < n; k += i)
                is_prime[k] = false;
    vector<int> primes;
    for (int i = 2; i < n; ++ i)
        if (is_prime[i])
            primes.push_back(i);
    return primes;
}
map<ll, int> prime_factorize(ll n, vector<int> const & primes) {
    map<ll, int> result;
    for (int p : primes) {
        if (n < p *(ll) p) break;
        while (n % p == 0) {
            result[p] += 1;
            n /= p;
        }
    }
    if (n != 1) result[n] += 1;
    return result;
}
vector<ll> list_factors(ll n, vector<int> const & primes) {
    vector<ll> result;
    result.push_back(1);
    for (auto it : prime_factorize(n, primes)) {
        ll p; int k; tie(p, k) = it;
        int size = result.size();
        REP (y, k) {
            REP (x, size) {
                result.push_back(result[y * size + x] * p);
            }
        }
    }
    sort(ALL(result));
    return result;
}

vector<int> solve(int n) {
    auto factors = list_factors(n, list_primes(sqrt(n) + 3));
    int d = factors.size();
    vector<vector<int> > dp(d);
    dp[0].push_back(0);
    REP (i, d) {
        sort(ALL(dp[i]));
        dp[i].erase(unique(ALL(dp[i])), dp[i].end());
        REP3 (j, i + 1, d) {
            if (factors[j] % factors[i] == 0) {
                int delta = factors[j] / factors[i] - 1;
                for (int s : dp[i]) {
                    dp[j].push_back(s + delta);
                }
            }
        }
    }
    return dp[d - 1];
}

int main() {
    int n; scanf("%d", &n);
    vector<int> answer = solve(n);
    printf("%d\n", (int)answer.size());
    for (int x : answer) {
        printf("%d ", x);
    }
    printf("\n");
    return 0;
}
```
