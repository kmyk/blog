---
layout: post
redirect_from:
  - /blog/2016/04/24/s8pc-2-f/
date: 2016-04-24T22:58:42+09:00
tags: [ "competitive", "writeup", "atcoder", "s8pc", "math" ]
"target_url": [ "https://beta.atcoder.jp/contests/s8pc-2/tasks/s8pc_2_f" ]
---

# square869120Contest #2 F - Range Sum Queries

## solution

数学。$f(a,b,c) = \Sigma\_{i=1}^a (b^{i-1} \cdot {}\_{c+a-i-1}C\_{a-i})$。$O(a)$。

$(a, b, c) = (6, 3, 4)$ぐらいの大きさまで手で解いてみると気付ける。

-   $a = 1$のとき答えは$1$
-   $a = 2$のとき答えは$b + c$
-   $a = 3$のとき答えは$b^2 + bc + {}\_{c+1}C_2$
-   $a = 4$のとき答えは$b^3 + b^2c + b{}\_{c+1}C_2 + {}\_{c+2}C_3$

## implementation

毎回`pow`してるので$O(a \log a)$。

``` c++
#include <iostream>
#include <vector>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;
ll powi(ll x, ll y, ll p) { x = (x % p + p) % p; ll z = 1; for (ll i = 1; i <= y; i <<= 1) { if (y & i) z = z * x % p; x = x * x % p; } return z; }
ll inv(ll x, ll p) { assert ((x % p + p) % p != 0); return powi(x, p-2, p); }
const ll mod = 1e9+7;
int main() {
    ll a, b, c; cin >> a >> b >> c;
    ll ans = 0;
    ll choose = 1;
    repeat (i,a) {
        ans += powi(b, a-i-1, mod) * choose;
        ans %= mod;
        choose *= (c+i) * inv(i+1, mod) % mod;
        choose %= mod;
    }
    cout << ans << endl;
    return 0;
}
```
