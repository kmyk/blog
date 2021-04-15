---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/368/
  - /blog/2016/05/14/yuki-368/
date: 2016-05-14T20:47:59+09:00
tags: [ "competitive", "writeup", "yukicoder", "primes" ]
"target_url": [ "http://yukicoder.me/problems/1048" ]
---

# Yukicoder No.368 LCM of K-products

## problem

-   $A = ( a_1, a_2, \dots a_N )$
-   $B = \\{ \Pi\_{x \in X} A_x \mid X \subset \\{ 1 \dots N \\}, \|X\| = K \\}$
-   $Z = \rm{lcm} B$

のとき、$Z \bmod 10^9+7$を答えよ。

## solution

積とLCMしか関連しないので、それぞれの素数に関して分けて考えることができる。

それぞれの素数$p$に関して、そのような$p^q \| Z$な$q$の最大を求めればよい。
$f_p(n) = \max \\{ q \mid p^q \| n \\}$とする。
$f(Z) = q$ならば$p^q \| b$な$b \in B$がある。
そのような$b$があるのは、$p^q \| a_i \cdot a_j \cdot \dots \cdot a_k$な$a_i, a_j, \dots, a_k$があるとき。
これは$q = f(a_i) + f(a_j) + \dots + f(a_k)$と書き直せる。
よって、各$a_i$に関し$f(a_i)$を計算し、それらを整列し大きい順に$K$個足し合わせれば、$f(Z)$が求まる。

あとは各$p$に関する$f_p(Z)$から、$Z$を構成する。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <numeric>
#include <map>
#include <cmath>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
typedef long long ll;

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
map<int,int> factors(int n, vector<int> const & primes) {
    map<int,int> result;
    for (int p : primes) {
        if (n < p * p) {
            result[n] += 1;
            break;
        }
        while (n % p == 0) {
            result[p] += 1;
            n /= p;
        }
    }
    return result;
}
ll powi(ll x, ll y, ll p) {
    x = (x % p + p) % p;
    ll z = 1;
    for (ll i = 1; i <= y; i <<= 1) {
        if (y & i) z = z * x % p;
        x = x * x % p;
    }
    return z;
}

const int mod = 1e9+7;
int main() {
    int n, k; cin >> n >> k;
    vector<int> xs(n); repeat (i,n) cin >> xs[i];
    int max_x = *max_element(xs.begin(), xs.end());
    vector<int> primes = sieve_of_eratosthenes(sqrt(max_x) + 1000);
    map<int,vector<int> > counts;
    for (int x : xs) {
        for (auto it : factors(x, primes)) {
            int p, cnt; tie(p, cnt) = it;
            counts[p].push_back(cnt);
        }
    }
    int ans = 1;
    for (auto it : counts) {
        int p; vector<int> cnts; tie(p, cnts) = it;
        int l = cnts.size();
        sort(cnts.rbegin(), cnts.rend());
        int cnt = accumulate(cnts.begin(), cnts.begin() + min(k, l), 0);
        ans = ans * powi(p, cnt, mod) % mod;
    }
    cout << ans << endl;
    return 0;
}
```

---

# Yukicoder No.368 LCM of K-products

-   Mon Jul  4 12:03:46 JST 2016
    -   `#include <cmath>`の漏れにより`CE`でrejudge食らった
