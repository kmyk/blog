---
layout: post
redirect_from:
  - /blog/2017/05/26/arc-061-f/
date: "2017-05-26T08:44:01+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "graph", "combination" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc061/tasks/arc061_d" ]
---

# AtCoder Regular Contest 061: F - 3人でカードゲーム / Card Game for Three

## solution

手札の中身でなくて手番の遷移に注目する。
組合せの総和の計算が問題となるが、Pascalの三角形によるDPの式から導かれる式を使う。
$O(M + K)$。

手番の遷移に注目する。
例えば`ABCBACCCCA`と手番が遷移してゲームが終了したとすると、$A$さんの手札は上から`BC`、$B$さんの手札は上から`CA???...`、$C$さんの手札は上から`BCCCA???...`だということが復元できる。
この手番の遷移の中には`A`が$N+1$回含まれ、$A$さんが勝つとすると最後と最初は必ず`A`。
`B`と`C`はそれぞれ高々$M,K$枚まで含まれる。
この遷移の列の長さ$l+1$を決めればその列の種類数は組合せを使って計算できる。
列の種類数はまずその中のどの位置に`A`が来るかで${}\_lC\_{N-1}$通り。
`B`と`C`を分配するが、`B`が$i$枚使われると決めると${}\_{l-N}C\_i$通り。足して$\sum\_i {}\_{l-N}C\_i$通り。
この列から復元できない範囲の$N+M+K-l$枚についてはまったくの自由なので$3^{N+M+K-l}$通り。
よってこれで求まる。

$\sum\_i {}\_{l-N}C\_i$を求めるのが遅い。
そこでPascalの三角形によるDPの式から導かれる式$\sum\_{0 \le r \le n} {}\_{n+1}C\_r = 2 \cdot \sum\_{0 \le r \le n} {}\_nC\_r$を使う。
区間が伸び縮みするときはその両端の分の補正を入れて$\sum\_{a+1 \le r \le b} {}\_{n+1}C\_r = 2 \cdot \sum\_{a \le r \le b} {}\_nC\_r - {}\_nC\_a - {}\_nC\_b$のようにできて、これで求まる。

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
int choose(int n, int r) { // O(n) at first time, otherwise O(\log n)
    if (n < r) return 0;
    r = min(r, n - r);
    return fact<mod>(n) *(ll) inv(fact<mod>(n-r), mod) % mod *(ll) inv(fact<mod>(r), mod) % mod;
}

constexpr ll mod = 1e9+7;
int main() {
    int n, m, k; scanf("%d%d%d", &n, &m, &k);
    ll result = 0;
    if (n == 0) {
        result += powmod(3, m + k, mod);
    } else {
        ll y = 1;
        repeat_from (l, n, n+m+k+1) {
            ll x = choose<mod>(l-1, n-1);
            // partial score
            /*
            ll y = 0;
            int yl = max(0, l-n-k);
            int yr = min(l-n, m) + 1; // [l, r)
            repeat_from (i, yl, yr) {
                y += choose<mod>(l-n, i);
            }
            y %= mod;
            */
            ll z = powmod(3, n+m+k-l, mod);
            result += x * y % mod * z % mod;
            // update
            y *= 2;
            if (l-n-k >= 0) y -= choose<mod>(l-n, l-n-k);
            if (m <= l-n) y -= choose<mod>(l-n, m);
            y %= mod;
            if (y < 0) y += mod;
        }
    }
    result %= mod;
    printf("%lld\n", result);
    return 0;
}
```
