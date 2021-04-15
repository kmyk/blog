---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc_064_f/
  - /writeup/algo/atcoder/arc-064-f/
  - /blog/2016/12/07/arc-064-f/
date: "2016-12-07T13:43:03+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "prime-factors", "palindrome" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc064/tasks/arc064_d" ]
---

# AtCoder Regular Contest 064: F - Rotated Palindromes

解けず。$1000$点だからとF openしたので座ってるだけになった。

## solution

回文$a$の周期性$d$で分類する。$O(d(N)^2)$。

回文$a$はちょうど$K^{\lceil \frac{N}{2} \rceil}$個存在する。
しかしこれを単に$N$倍しても答えにはならない。
何度か回転$f : a_0a_1a_2\dots a\_{n-1} \mapsto a_1a_2\dots a\_{n-1}a_0$すると他の回文と一致する場合がある。

ここで回文$a$をその周期で分類する。
回文の周期$d$とは、$f^d(a) = a$となるような最小の$d \ge 1$のこと。
ある周期$d$の回文の個数を(回転で一致する場合は同一視して)$\mathrm{num}(d)$とすると、
$\mathrm{ans} = \sum\_{d \| N} \mathrm{num(d)} \cdot d$となる。

$\mathrm{num}(d)$を求めよう。
単に$K^{\lceil \frac{d}{2} \rceil}$個だと$d'\|d$な$d' \lt d$を重複して数えること、$d$が偶数なら$\frac{d}{2}$回の回転で他の周期$d$の回文と衝突することから、$\mathrm{num}(d) = (K^{\lceil \frac{d}{2} \rceil} - \sum\_{d'\|d \land d'\lt d} \mathrm{num}(d'))\cdot \frac{1}{2 - d \bmod 2}$となる。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <set>
#include <map>
#include <cmath>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
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
vector<ll> list_prime_factrors(ll n, vector<int> const & primes) {
    vector<ll> result;
    for (int p : primes) {
        if (n < p *(ll) p) break;
        while (n % p == 0) {
            result.push_back(p);
            n /= p;
        }
    }
    if (n != 1) result.push_back(n);
    return result;
}
ll powi(ll x, ll y, ll p) { // O(log y)
    assert (y >= 0);
    x = (x % p + p) % p;
    ll z = 1;
    for (ll i = 1; i <= y; i <<= 1) {
        if (y & i) z = z * x % p;
        x = x * x % p;
    }
    return z;
}

const ll mod = 1e9+7;
int main() {
    int n, k; cin >> n >> k;
    set<int> ds { 1 };
    for (ll p : list_prime_factrors(n, sieve_of_eratosthenes(sqrt(n) + 3))) {
        set<int> prev_ds = ds;
        for (int d : prev_ds) {
            ds.insert(d * p);
        }
    }
    ll ans = 0;
    map<int,ll> num;
    for (int d : ds) {
        ll acc = powi(k, (d+1)/2, mod);
        for (int d2 : ds) if (d % d2 == 0 and d2 < d) {
            acc -= num[d2];
        }
        num[d] = (acc % mod + mod) % mod;
        ans += num[d] * d / (d % 2 == 0 ? 2 : 1);
    }
    ans %= mod;
    cout << ans << endl;
    return 0;
}
```
