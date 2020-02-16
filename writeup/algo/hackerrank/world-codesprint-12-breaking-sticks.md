---
layout: post
redirect_from:
  - /blog/2017/12/31/hackerrank-world-codesprint-12-breaking-sticks/
date: "2017-12-31T16:26:34+09:00"
tags: [ "competitive", "writeup", "hackerrank", "codesprint", "primes", "dp" ]
"target_url": [ "https://www.hackerrank.com/contests/world-codesprint-12/challenges/breaking-sticks" ]
---

# HackerRank World CodeSprint 12: Breaking Sticks

## problem

それぞれ長さ$a\_i$のチョコレートの欠片たちが与えられる。
長さ$b \ge 1$の欠片をひとつとその非自明な約数$d \ne 1, n$を選んで欠片を$\frac{b}{d}$等分することを繰り返す。この操作は最高何回できるか。

## solution

長さ$i$の欠片を砕き切るまでに何回操作できるかを$\mathrm{dp}(i)$とおいてDP。
$a \le 10^{12}$と大きいが出現する欠片の長さはすべてこの約数であるため小さい。
約数$d$は素数に限ってよいが$\sqrt{a\_i}$まで試し割りが必要。これが効いて計算量は$O(\sum \sqrt{a\_i})$。

約数の個数$d(n)$の近似について。
[約数個数関数の上からの評価 - INTEGERS](http://integers.hatenablog.com/entry/2016/07/20/015425)によると$d(n) \le \exp(O(\frac{\log n}{\log \log n}))$らしい。
$O(\dots)$を無視して$\exp \frac{\log 10^{12}}{\log \log 10^{12}} \approx 4126.8$。
$a = 2 \cdot 3 \cdot 5 \cdot \dots \cdot 29 \cdot 31 = 200560490130$としても$d(a) = 2048$。

## implementation

``` c++
#include <bits/stdc++.h>
using ll = long long;
using namespace std;
template <class T> inline void chmax(T & a, T const & b) { a = max(a, b); }

vector<bool> sieve_of_eratosthenes(int n) { // enumerate primes in [2,n] with O(n log log n)
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

vector<int> primes = list_primes(1e6 + 100);
unordered_map<ll, ll> memo;
ll longest_sequence(ll a) {
    if (memo.count(a)) return memo[a];
    if (a == 1) return memo[a] = 1;
    ll acc = 0;
    for (auto pk : prime_factorize(a, primes)) {
        ll p = pk.first;
        chmax(acc, 1 + longest_sequence(a / p) * p);
    }
    return memo[a] = acc;
}

int main() {
    int n; cin >> n;
    ll result = 0;
    while (n --) {
        ll a; cin >> a;
        result += longest_sequence(a);
    }
    cout << result << endl;
    return 0;
}
```
