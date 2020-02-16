---
layout: post
alias: "/blog/2017/01/15/arc-067-e/"
date: "2017-01-15T22:49:44+09:00"
tags: [ "competitive", "writeup", "arc", "atcoder", "dp", "combination" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc067/tasks/arc067_c" ]
---

# AtCoder Regular Contest 067: E - Grouping

提出したらsampleだけTLEでそれ以外がACし、AtCoderの点数付けの性質により、TLEだが満点になった。

後でgccでなくclangで提出しなおしたら速くなってきちんとACした。以前はgccの方が速いと知られていたはずだが、いつの間にか逆転したのだろうか。

## solution

DP。グループの大きさを$i$まで見て合計$j$人使ったときの場合の数$\mathrm{dp}(i,j)$を計算する。
次に使うグループの大きさが$x$でこれを$y$グループ使うとすると、$xy \le N$が成り立つことから計算量が落ちる。$O(N^2\log N)$。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < int(n); ++(i))
using ll = long long;
using namespace std;
const int mod = 1e9+7;

ll powmod(ll x, ll y) { // O(log y)
    assert (y >= 0);
    x %= mod; if (x < 0) x += mod;
    ll z = 1;
    for (ll i = 1; i <= y; i <<= 1) {
        if (y & i) z = z *(ll) x % mod;
        x = x *(ll) x % mod;
    }
    return z;
}
ll inv(ll x) { // p must be a prime, O(log p)
    assert ((x % mod + mod) % mod != 0);
    return powmod(x, mod-2);
}
ll fact(ll n) {
    static vector<ll> memo(1,1);
    if (memo.size() <= n) {
        ll l = memo.size();
        memo.resize(n+1);
        repeat_from (i,l,n+1) memo[i] = memo[i-1] *(ll) i % mod;
    }
    return memo[n];
}
ll choose(ll n, ll r) { // O(n) at first time, otherwise O(1)
    if (n < r) return 0;
    r = min(r, n - r);
    return fact(n) *(ll) inv(fact(n-r)) % mod *(ll) inv(fact(r)) % mod;
}

int main() {
    ll n, a, b, c, d; cin >> n >> a >> b >> c >> d;
    vector<ll> cur(n+1), prv;
    cur[0] = 1;
    repeat_from (size,a,b+1) {
        prv = cur;
        repeat_from (count,c,d+1) {
            ll k = fact(size*count) *(ll) inv(powmod(fact(size), count)) % mod * inv(fact(count)) % mod;
            repeat (i,n) if (i + size*count < n+1 and prv[i]) {
                cur[i + size*count] += prv[i] *(ll) choose(n-i, size*count) % mod * k % mod;
            }
        }
        repeat (i,n+1) cur[i] %= mod;
    }
    cout << cur[n] << endl;
    return 0;
}
```
