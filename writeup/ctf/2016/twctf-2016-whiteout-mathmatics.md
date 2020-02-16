---
layout: post
alias: "/blog/2016/09/05/twctf-2016-whiteout-mathmatics/"
date: "2016-09-05T13:25:34+09:00"
tags: [ "ctf", "writeup", "ppc", "mmactf", "twctf", "esolang", "whitespace" ]
"target_url": [ "https://score.ctf.westerns.tokyo/problems/35" ]
---

# Tokyo Westerns/MMA CTF 2nd 2016: Whiteout Mathmatics

<!-- {% raw %} -->

Whitespace is a language only for polyglot.
Such a use of this language is very strange.
But I don't know the appropriate language. piet, grass or forth?

## solution

Simplifying the code, finally it becomes like below. The answer is for $a = 100, b = 1000000000000$.
<http://ws2js.luilak.net/interpreter.html> was useful.

``` python
#!/usr/bin/env python3
def sum_factors(x):
    z = 0
    for y in range(1, x+1):
        if x % y == 0:
            z += y
    return z

a = int(input())
b = int(input())
c = -1
for i in range(a, b + 1):
    print(i, sum_factors(i))
    c = max(c, sum_factors(i))

print('TWCTF{%d}' % c)
```

Optimize it.
The sum $5618427494400$ for $n = 995886571680$ is the answer. `TWCTF{5618427494400}`.

``` c++
#include <iostream>
#include <vector>
#include <map>
#include <tuple>
#include <cmath>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;
template <class T> void setmax(T & a, T const & b) { if (a < b) a = b; }
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
map<ll,int> factors(ll n, vector<int> const & primes) {
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


ll sum_factors(ll n, vector<int> const & primes) {
    ll ans = 1;
    for (auto it : factors(n, primes)) {
        ll p; int cnt; tie(p, cnt) = it;
        ll acc = 0; ll p_i = 1;
        repeat (i,cnt+1) {
            acc += p_i;
            if (i != cnt /* to avoid overflow */) p_i *= p;
        }
        ans *= acc;
    }
    return ans;
}
pair<ll,ll> dfs(int i, ll n, ll acc, ll a, ll b, vector<int> const & primes) {
    pair<ll,ll> result = { acc, n };
    if (i >= 30) return result;
    int k = 0;
    ll pk = 1;
    ll pkacc = 1;
    for (; n * pk * primes[i] <= b; ++ k) {
        pk *= primes[i];
        pkacc += pk;
    }
    setmax(result, make_pair(acc * pkacc, n * pk));
    for (; k >= 0; -- k) {
        setmax(result, dfs(i+1, n * pk, acc * pkacc, a, b, primes));
        pkacc -= pk;
        pk /= primes[i];
    }
    return result;
}
int main(int argc, char **argv) {
    assert (argc == 1);
    ll a, b; cin >> a >> b;
    vector<int> primes = sieve_of_eratosthenes(sqrt(b) + 3);
    auto it = dfs(0, 1, 1, a, b, primes);
    cout << it.first << ' ' << it.second << endl;
    return 0;
}
```

<!-- {% endraw %} -->
