---
layout: post
redirect_from:
  - /writeup/algo/aoj/2335/
  - /blog/2017/06/01/aoj-2335/
date: "2017-06-01T04:18:37+09:00"
tags: [ "competitive", "writeup", "aoj", "combination" ]
"target_url": [ "http://judge.u-aizu.ac.jp/onlinejudge/description.jsp?id=2335" ]
---

# AOJ 2335: １０歳の動的計画 / 10-Year-Old Dynamic Programming

折り返しとかいう天才解法は思い付けなかったので筋肉した。

## solution

組み合わせで頑張る。$O(N+M+K^2)$。

$K$回の寄り道の内で左に進む回数を$i$と固定する。
$N+M+2K$回の移動の内$N+2i$回が左右の移動で$M+2(K-i)$回が上下の移動。
この分け方は${}\_{N+M+2K}C\_{N+2i}$通り。
左右にだけ注目する。
単純には左に動く位置を選んで${}\_{N+2i}C\_i$通りであるが、負の座標には侵入できないためこれではだめ。
なので負の座標に侵入するような動き方の数を数えて引く。
直接求めるのは簡単でないので、初めて負の座標に侵入するのが$t$回目の左への移動だとしてこの$t$で分割する。
そうすると漸化式$\mathrm{forbidden}(t) = {}\_{2t-1}C\_t - \sum\_{1 \le t' \lt t} {}\_{2(t-t')}C\_{t-t'} \mathrm{forbidden}(t')$で求まる。

## implementation

``` c++
#include <cstdio>
#include <vector>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < int(n); ++(i))
using ll = long long;
using namespace std;

ll powmod(ll x, ll y, ll p) { // O(log y)
    assert (0 <= x and x < p);
    assert (0 <= y);
    ll z = 1;
    for (ll i = 1; i <= y; i <<= 1) {
        if (y & i) z = z * x % p;
        x = x * x % p;
    }
    return z;
}
ll inv(ll x, ll p) { // p must be a prime, O(log p)
    assert ((x % p + p) % p != 0);
    return powmod(x, p-2, p);
}
template <int mod>
int fact(int n) {
    static vector<int> memo(1,1);
    if (memo.size() <= n) {
        int l = memo.size();
        memo.resize(n+1);
        repeat_from (i,l,n+1) memo[i] = memo[i-1] *(ll) i % mod;
    }
    return memo[n];
}
template <int mod>
int inv_fact(int n) {
    static vector<int> memo(1,1);
    if (memo.size() <= n) {
        int l = memo.size();
        memo.resize(n+1);
        repeat_from (i,l,n+1) if (i >= 1) memo[i] = inv(fact<mod>(i), mod);
    }
    return memo[n];
}
template <int mod>
int choose(int n, int r) { // O(n) at first time, otherwise O(\log n)
    if (n < r) return 0;
    r = min(r, n - r);
    return fact<mod>(n) *(ll) inv_fact<mod>(n-r) % mod *(ll) inv_fact<mod>(r) % mod;
}

constexpr int mod = 1e9+7;
int main() {
    int n, m, k; scanf("%d%d%d", &n, &m, &k);
    vector<int> forbidden(k+1);
    repeat (i, k+1) {
        ll acc = 0;
        repeat (j, i) {
            int l = i - j;
            acc += forbidden[j] *(ll) choose<mod>(2*l, l) % mod;
        }
        forbidden[i] = (choose<mod>(2*i-1, i) - acc % mod + mod) % mod;
    }
    ll result = 0;
    repeat (i, k+1) {
        int l = k - i;
        ll a = 0;
        repeat (j, i+1) {
            a += forbidden[j] *(ll) choose<mod>(n + 2*(i-j)+1, i-j) % mod;
        }
        a = (choose<mod>(n + 2*i, i) -(ll) a % mod + mod) % mod;
        ll b = 0;
        repeat (j, l+1) {
            b += forbidden[j] *(ll) choose<mod>(m + 2*(l-j)+1, l-j) % mod;
        }
        b = (choose<mod>(m + 2*l, l) -(ll) b % mod + mod) % mod;
        result += choose<mod>(n + m + 2*k, n + 2*i) *(ll) a % mod * b % mod;
    }
    printf("%lld\n", result % mod);
    return 0;
}
```
