---
layout: post
redirect_from:
  - /blog/2018/03/31/codechef-cook91-cthree/
date: "2018-03-31T02:12:55+09:00"
tags: [ "competitive", "writeup", "codechef", "prime-factors" ]
"target_url": [ "https://www.codechef.com/COOK91/problems/CTHREE" ]
---

# CodeChef February Cook-Off 2018: Chef and Tuples

## problem

自然数$N$と$3$つ組$(a, b, c)$が与えられる。
$3$つ組$(x, y, z)$であって$xyz = N \land x \le a \land y \le b \land z \le c$を満たすようなものの数を数えよ。

## solution

総当たり。$O(d(N)^2)$。

$N$の約数の個数$d(N)$は最大でも$1000$のオーダーである。
$x, y$についてこれらから総当たりして間に合う。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
using ll = long long;
using namespace std;

vector<bool> sieve_of_eratosthenes(int n) {
    vector<bool> is_prime(n + 1, true);
    is_prime[0] = is_prime[1] = false;
    for (int i = 2; i * i <= n; ++ i)
        if (is_prime[i])
            for (int k = 2 * i; k <= n; k += i)
                is_prime[k] = false;
    return is_prime;
}
vector<int> list_primes(int n) {
    auto is_prime = sieve_of_eratosthenes(n);
    vector<int> primes;
    for (int i = 2; i <= n; ++ i)
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
    return result;
}
vector<int> primes = list_primes(1e5);

ll solve(ll n, ll a, ll b, ll c) {
    ll cnt = 0;
    vector<ll> xs = list_factors(n, primes);
    for (ll x : xs) if (x <= a) {
        for (ll y : xs) if (y <= b) {
            if (n % (x * y) == 0) {
                ll z = n / (x * y);
                if (z <= c) {
                    cnt += 1;
                }
            }
        }
    }
    return cnt;
}

int main() {
    int t; cin >> t;
    while (t --) {
        ll n, a, b, c; cin >> n >> a >> b >> c;
        ll result = solve(n, a, b, c);
        cout << result << endl;
    }
    return 0;
}
```
