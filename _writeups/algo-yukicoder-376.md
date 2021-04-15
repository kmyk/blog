---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/376/
  - /blog/2016/06/05/yuki-376/
date: 2016-06-05T02:46:52+09:00
tags: [ "competitive", "writeup", "yukicoder", "prime" ]
"target_url": [ "http://yukicoder.me/problems/547" ]
---

# Yukicoder No.376 立方体のN等分 (2)

[No.375 立方体のN等分 (1)](http://yukicoder.me/problems/489)とは入力の制約だけが違うので、同じコードで通る。

## solution

$T\_\max = n - 1$は明らか。

$T\_\min$に関して、

-   $\min T\_\min = (p - 1) + (q - 1) + (r - 1)$
-   $\text{sub to. \;} p * q * r = n$

である。

適当に$p, q, r$を列挙すればいい。
素因数の総数は$\log n$個以下なので、間に合う。

## implementation

競技なのに珍しいなあと言いながら、継続を使った。
しかしみんなもっと簡潔で綺麗なコードで提出していたので悲しい。
素因数分解してしまうのでなくて、因数を列挙してやるのがよいっぽい。

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <cmath>
#include <map>
#include <functional>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
template <class T> bool setmin(T & l, T const & r) { if (not (r < l)) return false; l = r; return true; }
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

const ll inf = 1e18+9;
template <typename F>
ll go(ll n, map<ll,int> & ps, map<ll,int>::iterator it, ll acc, F cont) {
    if (it == ps.end()) {
        return cont(n, ps, acc);
    } else {
        ll p; int cnt; tie(p, cnt) = *it;
        ++ it;
        ll ans = inf;
        repeat (i,cnt+1) {
            setmin(ans, go(n, ps, it, acc, cont));
            ps[p] -= 1;
            acc *= p;
            n /= p;
        }
        ps[p] += cnt+1;
        return ans;
    }
}
template <typename F>
ll go(ll n, map<ll,int> ps, F cont) {
    return go(n, ps, ps.begin(), 1, cont);
}

int main() {
    ll n; cin >> n;
    vector<int> primes = sieve_of_eratosthenes(ceil(sqrt(n)));
    map<ll,ll> memo;
    auto ps = factors(n, primes);
    ll ans = go(n, ps, [&](ll n, map<ll,int> ps, ll a) {
        if (not memo.count(n)) {
            memo[n] = go(n, ps, [&](ll c, map<ll,int> ps, ll b) {
                return (b - 1) + (c - 1);
            });
        }
        return (a - 1) + memo[n];
    });
    cout << ans << ' ' << n-1 << endl;
    return 0;
}
```

<hr>

-   Mon Jul  4 12:03:46 JST 2016
    -   `#include <cmath>`の漏れにより`CE`でrejudge食らった
