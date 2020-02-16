---
layout: post
alias: "/blog/2017/01/15/arc-067-c/"
date: "2017-01-15T22:49:41+09:00"
tags: [ "competitive", "writeup", "arc", "atcoder" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc067/tasks/arc067_a" ]
---

# AtCoder Regular Contest 067: C - Factors of Factorial

昨日dwaconでやったじゃんと思いながら書いた。

## solution

普通にやる。$O(N \log N)$ぐらい。

$n = p_1^{k_1} p_2^{k_2} \dots p_l^{k_l}$と素因数分解できるとき約数の個数$d(n) = (1 + k_1)(1 + k_2)\dots (1 + k_l)$なので、$N!$を構成する$1,2,\dots,N$のそれぞれを素因数分解して指数部を足し合わせる。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <map>
#include <cmath>
#define repeat_from(i,m,n) for (int i = (m); (i) < int(n); ++(i))
using ll = long long;
using namespace std;

vector<int> sieve_of_eratosthenes(int n) { // enumerate primes in [2,n] with O(n log log n)
    vector<bool> is_prime(n+1, true);
    is_prime[0] = is_prime[1] = false;
    for (int i = 2; i*i <= n; ++i)
        if (is_prime[i])
            for (int k = i+i; k <= n; k += i)
                is_prime[k] = false;
    vector<int> primes;
    for (int i = 2; i <= n; ++i)
        if (is_prime[i])
            primes.push_back(i);
    return primes;
}
map<ll,int> prime_factrorize(ll n, vector<int> const & primes) {
    map<ll,int> result;
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

const int mod = 1e9+7;
int main() {
    int n; cin >> n;
    vector<int> primes = sieve_of_eratosthenes(sqrt(n) + 3);
    map<ll,int> factors;
    repeat_from (i,1,n+1) {
        for (auto it : prime_factrorize(i, primes)) {
            int p, cnt; tie(p, cnt) = it;
            factors[p] += cnt;
        }
    }
    ll ans = 1;
    for (auto it : factors) {
        int cnt = it.second;
        ans = ans * (1 + cnt) % mod;
    }
    cout << ans << endl;
    return 0;
}
```
