---
layout: post
redirect_from:
  - /blog/2016/01/21/hackerrank-101hack33-average-modulo/
date: 2016-01-21T21:33:26+09:00
tags: [ "competitive", "writeup", "hackerrank", "dp", "math" ]
---

# Hackerrank 101 Hack Jan 2016 Average Modulo

本番では解けず。簡単ではないが、解けるべき問題。

## [Average Modulo](https://www.hackerrank.com/contests/101hack33/challenges/average-modulo)

### 問題

数列$a$がある。整数$p,k$が指定される。長さ$k$以上の区間$[l,r)$で、$\frac{\Sigma\_{l \le i \lt r} a_i \pmod{p}}{r - l}$を考え、この最大値を有理数として出力せよ。

### 解法

区間の長さが$2k$未満と分かるので、これを全部試して$O(nk)$。

区間$I$の長さが$2k$であるとする。長さ$k$の区間$I_x,I_y$に分割できる。
$s(I) = \Sigma\_{i \in I} a_i$として、$\frac{s(I)}{2k} = \frac{s(I_x) + s(I_y)}{k + k} \le {\rm max} \\{ \frac{s(I_x)}{k}, \frac{s(I_y)}{k} \\}$となる。$s$を$s'(I) = s(I) \bmod p$で置き換えてもこれは変わらないため、区間の長さは$2k$未満となる。

### 実装

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define repeat_reverse(i,n) for (int i = (n)-1; (i) >= 0; --(i))
typedef long long ll;
using namespace std;
ll gcd(ll a, ll b) {
    if (b <= a) swap(a,b);
    while (a) { ll c = a; a = b % c; b = c; }
    return b;
}
void solve() {
    ll n, mod, k; cin >> n >> mod >> k;
    vector<ll> a(n); repeat (i,n) cin >> a[i];
    ll p = 0, q = 1;
    vector<ll> dp(2*k);
    repeat (i,n) {
        repeat_reverse (j,2*k-1) dp[j+1] = (dp[j] + a[i]) % mod;
        repeat_from (j,k,2*k) {
            if (p*(j) < dp[j]*q) {
                p = dp[j];
                q = j;
                ll t = gcd(p,q);
                p /= t;
                q /= t;
            }
        }
    }
    cout << p << ' ' << q << endl;
}
int main() {
    int t; cin >> t;
    repeat (i,t) solve();
    return 0;
}
```
