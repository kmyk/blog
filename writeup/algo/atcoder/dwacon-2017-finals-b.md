---
layout: post
alias: "/blog/2017/01/16/dwacon-2017-finals-b/"
date: "2017-01-16T16:27:14+09:00"
tags: [ "competitive", "writeup", "dwacon", "atcoder", "mo-algorithm" ]
"target_url": [ "https://beta.atcoder.jp/contests/dwacon2017-honsen/tasks/dwango2017final_b" ]
---

# 第3回 ドワンゴからの挑戦状 本選: B - ニワンゴくんの約数

## solution

小さい素数は個別に累積和して$O((N+Q) \pi(\sqrt{\max x_i}))$、ただし$\pi(x)$は$x$以下の素数の数で$\pi(x) \sim \frac{x}{\log x}$。
大きい素数にMo's algorithmして$O((N+Q)\sqrt{N})$。
合わせて展開すると$O(N+Q)(\sqrt{N} + \frac{\sqrt{\max x_i}}{\log{\max x_i}})$。

単純には$x_i$をそれぞれ素因数分解して指数部を足し合わせればよく、$O((N+Q)\pi(\max x_i))$。これは$10^5$の$2$乗ぐらいなのでかなり厳しい。

素数の種類数$\pi(\max x_i)$を計算量から落としたい。
そこで素数をその大きさ、特に$\sqrt{\max x_i}$との大小で分類することを考える。
これより小さい素数は$\pi(\sqrt{\max x_i})$個なので$O((N+Q) \pi(\sqrt{\max x_i}))$で処理してしまえる。
また、これより大きい素数はそれぞれの$x_i$の中に高々$1$種類しか現れえない。
与えられた区間$[l,r)$中の大きい素数を集計する操作が高速にできればよく、区間$[l,r)$の結果から$[l \pm 1,r)$や$[l,r \pm 1)$の結果を作るのは大きい素数が$1$種類だけなので$O(1)$、よってMo's algorithmを使って全体で$O((N+Q)\sqrt{N})$で処理できる。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <numeric>
#include <map>
#include <cmath>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using ll = long long;
using namespace std;
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

ll powmod(ll x, ll y, ll p) { // O(log y)
    assert (y >= 0);
    x %= p; if (x < 0) x += p;
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
map<int,int> prime_factrorize(int n, vector<int> const & primes) {
    map<int,int> result;
    for (int p : primes) {
        if (n < p * p) break;
        while (n % p == 0) {
            result[p] += 1;
            n /= p;
        }
    }
    if (n != 1) result[n] += 1;
    return result;
}

const int mod = 1e9+7;
int main() {
    // input
    int n, q; cin >> n >> q;
    vector<int> x(n); repeat (i,n) cin >> x[i];
    vector<int> l(q), r(q); repeat (i,q) { cin >> l[i] >> r[i]; -- l[i]; } // [l, r)
    // prepare factors
    int max_x = *whole(max_element, x);
    int sqrt_max_x = sqrt(max_x) + 3;
    vector<map<int,int> > f(n); repeat (i,n) f[i] = prime_factrorize(x[i], sieve_of_eratosthenes(sqrt_max_x));
    vector<int> primes;
    map<int,int> count;
    repeat (i,n) {
        for (auto it : f[i]) {
            int p, cnt; tie(p, cnt) = it;
            primes.push_back(p);
            count[p] += cnt;
        }
    }
    whole(sort, primes);
    primes.erase(whole(unique, primes), primes.end());
    map<int,int> index; repeat (i,primes.size()) index[primes[i]] = i;
    int small_p_size = 0; while (small_p_size < primes.size() and primes[small_p_size] < sqrt_max_x) ++ small_p_size;
    vector<vector<int> > small_acc = vectors(small_p_size, n+1, int());
    vector<int> unique_acc(n+1);
    vector<int> large_prime(n, -1);
    repeat (j,n) {
        for (auto it : f[j]) {
            int p, cnt; tie(p, cnt) = it;
            int i = index[p];
            if (i < small_p_size) {
                small_acc[i][j+1] += cnt;
            } else if (count[p] == 1) {
                unique_acc[j+1] += 1;
            } else {
                assert (cnt == 1);
                assert (large_prime[j] == -1);
                large_prime[j] = i - small_p_size;
            }
        }
    }
    repeat (i,small_p_size) repeat (j,n) small_acc[i][j+1] += small_acc[i][j];
    repeat (j,n) unique_acc[j+1] += unique_acc[j];
    // Mo's algorithm
    int sqrt_n = sqrt(n);
    vector<int> ixs(q);
    whole(iota, ixs, 0);
    whole(sort, ixs, [&](int i, int j) {
        return make_pair(l[i] / sqrt_n, r[i]) < make_pair(l[j] / sqrt_n, r[j]);
    });
    vector<int> ans(q);
    int l_cur = 0, r_cur = 0; // [l, r)
    vector<int> large_count(primes.size() - small_p_size);
    int large_acc = 1;
    vector<int> inv_table(n+3); repeat (i,inv_table.size()) inv_table[i] = i ? inv(i, mod) : 0;
    auto modify = [&](int i, int delta) {
        if (i == -1) return;
        assert (1 + large_count[i] < inv_table.size());
        large_acc = large_acc *(ll) inv_table[1 + large_count[i]] % mod;
        large_count[i] += delta;
        large_acc = large_acc *(ll) (1 + large_count[i]) % mod;
    };
    for (int i : ixs) {
        while (l[i] < l_cur) modify(large_prime[-- l_cur], + 1);
        while (r_cur < r[i]) modify(large_prime[r_cur ++], + 1);
        while (l_cur < l[i]) modify(large_prime[l_cur ++], - 1);
        while (r[i] < r_cur) modify(large_prime[-- r_cur], - 1);
        int acc = 1;
        acc = acc *(ll) large_acc % mod;
        acc = acc *(ll) powmod(2, unique_acc[r_cur] - unique_acc[l_cur], mod) % mod;
        repeat (i,small_p_size) acc = acc *(ll) (1 + small_acc[i][r_cur] - small_acc[i][l_cur]) % mod;
        ans[i] = acc;
    }
    // output
    repeat (i,q) cout << ans[i] << endl;
    return 0;
}
```
