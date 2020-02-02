---
layout: post
alias: "/blog/2016/09/24/code-festival-2014-final-g/"
date: "2016-09-24T10:45:46+09:00"
title: "CODE FESTIVAL 2014 決勝 G - 魔方陣"
tags: [ "competitive", "writeup", "atcoder", "codefestival" ]
"target_url": [ "https://beta.atcoder.jp/contests/code-festival-2014-final-open/tasks/code_festival_final_g" ]
---

$2$年越しのAC。ただしkmjpさんの解説をちら見した。

## solution

「積バージョンの魔方陣」ということであるが、素因数分解してそれぞれの指数ごとに考えれば、普通の和の魔方陣の重ね合わせである。
$N \le 10^{12}$であるが$\log$がかかるのであまり大きくはならない。

魔方陣はその中心の数を$n$として以下のように試せば列挙できる。

$$ \begin{pmatrix}
    a       & b    & 3n-a-b  \\\\
    4n-2a-b & n    & 2a+b-2n \\\\
    a+b-n   & 2n-b & 2n-a
\end{pmatrix} $$

これを各素因数ごとに列挙して、適当に足し合わせればよい。
回転反転は区別して持っておき、最後に$8$で割る。
座標圧縮の要領で小さくしておくと楽。

## note

どの魔方陣も以下の重ね合わせで表現できるように思う。問題解くのには使えなかった。

$$ \begin{pmatrix}
    2 & 0 & 1 \\\\
    0 & 1 & 2 \\\\
    1 & 2 & 0
\end{pmatrix}, \begin{pmatrix}
    1 & 1 & 1 \\\\
    1 & 1 & 1 \\\\
    1 & 1 & 1
\end{pmatrix} $$

## implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <array>
#include <map>
#include <numeric>
#include <tuple>
#include <cmath>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) y) { return (f)(begin(y), end(y), ## __VA_ARGS__); })(x)
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

template <typename T, size_t N>
map<T,int> coordinate_compression_map(array<T,N> const & xs) { // modified: don't sort
    array<int,N> ys = {};
    whole(iota, ys, 0);
    // whole(sort, ys, [&](int i, int j) { return xs[i] < xs[j]; });
    map<T,int> f;
    for (int i : ys) {
        if (not f.count(xs[i])) { // make unique
            int j = f.size();
            f[xs[i]] = j; // f[xs[i]] has a side effect, increasing the f.size()
        }
    }
    return f;
}
template <typename T, size_t N>
array<int,N> apply_compression(map<T,int> const & f, array<T,N> const & xs) {
    array<int,N> ys = {};
    repeat (i,N) ys[i] = f.at(xs[i]);
    return ys;
}

typedef array<int,9> square_t;
square_t operator * (int a, square_t b) { repeat (i,9) b[i] *= a; return b; }
square_t operator + (square_t a, square_t b) { repeat (i,9) a[i] += b[i]; return a; }
square_t compress(square_t a) {
    return apply_compression(coordinate_compression_map(a), a);
}
const square_t initial_square  = { { 0, 0, 0, 0, 0, 0, 0, 0, 0 } };

typedef map<square_t,ll> square_set_t;
square_set_t square_set(int n) {
    square_set_t xs;
    repeat (a,2*n+1) {
        repeat (b,2*n+1) {
            array<int,9> x = { {
                a,         b,     3*n-a-b,
                4*n-2*a-b, n,     2*a+b-2*n,
                a+b-n,     2*n-b, 2*n-a, } };
            if (*whole(min_element, x) >= 0) {
                xs[compress(x)] += 1;
            }
        }
    }
    return xs;
}
square_set_t merge_set(square_set_t const & xs, square_set_t const & ys) {
    square_set_t zs;
    for (auto x : xs) {
        for (auto y : ys) {
            square_t z = compress(x.first + 100*y.first);
            zs[z] += x.second * y.second;
        }
    }
    return zs;
}
int count_distinct(square_set_t const & xs) {
    int y = 0;
    for (auto it : xs) {
        if (whole(count, it.first, 8)) {
            y += it.second;
        }
    }
    return y;
}

int main() {
    ll n; cin >> n;
    map<square_t,ll> acc;
    acc[initial_square] += 1;
    map<ll,int> ps = factors(n, sieve_of_eratosthenes(sqrt(n) + 3));
    for (auto it : ps) {
        ll p; int cnt; tie(p, cnt) = it;
        acc = merge_set(acc, square_set(cnt));
    }
    ll ans = count_distinct(acc);
    assert (ans % 8 == 0);
    cout << ans/8 << endl;
    return 0;
}
```
