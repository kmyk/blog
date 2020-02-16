---
layout: post
alias: "/blog/2016/08/21/agc-003-d/"
date: "2016-08-21T23:55:23+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc", "boost", "normalization" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc003/tasks/agc003_d" ]
---

# AtCoder Grand Contest 003 D - Anticube

素因数分解の指数を$3$で割るぐらいは気付いていたが、正規化は思い付かず。

## solution

editorial: <https://beta.atcoder.jp/contests/agc003/data/agc/003/editorial.pdf>

立方数で割って正規化する。
整数$a \in \mathbb{N}$に対し$\mathrm{norm}(a) = \min \\{ b \mid \exists c. bc^3 = a \\} \in \mathbb{N}$とする。
立方数かどうかに関して、各$s_i$を$\mathrm{norm}(s_i)$で置き換えて問題ない。

その対になる数も同様に正規化することができ、一意になる。
つまり、$\mathrm{pair}(a) = \min \\{ b \mid \exists c. ab = c^3 \\} \in \mathbb{N}$である。
$\mathrm{pair}(a) = \mathrm{norm}(a^2)$として計算できる。

入力を正規化してまとめておけば、整数$a = \mathrm{norm}(a)$と衝突しうる数は$\mathrm{pair}(a)$のみであり、その個数の多い方を採用すればよいことになる。ただし、$1 = \mathrm{pair}(1)$であるので、これは特別に処理する必要がある。

## implementation

overflowを回避する部分が面倒だったのでboostさんにお願いした。

``` c++
#include <cstdio>
#include <vector>
#include <cmath>
#include <algorithm>
#include <map>
#include <set>
#include <tuple>
#include <cassert>
#include <boost/multiprecision/cpp_int.hpp>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) y) { return (f)(begin(y), end(y), ## __VA_ARGS__); })(x)
typedef long long ll;
typedef boost::multiprecision::cpp_int integer;
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
integer sq(integer x) { return x*x; }
integer cubed(integer x) { return x*x*x; }
integer norm(integer s, vector<int> const & primes) {
    for (int p : primes) {
        if (s < p) break;
        while (s % cubed(p) == 0) {
            s /= cubed(p);
        }
    }
    assert (s >= 1);
    return s;
}
integer inv(integer s, vector<int> const & primes) {
    integer t = 1;
    for (int p : primes) {
        if (s % p == 0) {
            if (s % sq(p) == 0) {
                t *= p;
                s /= sq(p);
            } else {
                t *= sq(p);
                s /= p;
            }
        }
    }
    if (s != 1) {
        integer r = sqrt(s);
        if (s == r * r) {
            t *= r;
        } else {
            t *= s * s;
        }
    }
    assert (t >= 1);
    return t;
}

int main() {
    // input
    int n; scanf("%d", &n);
    vector<ll> s(n); repeat (i,n) scanf("%lld", &s[i]);
    // compute
    vector<int> primes = sieve_of_eratosthenes(pow(*whole(max_element, s), 1/3.) + 3);
    map<integer, int> f;
    repeat (i,n) {
        integer x = norm(s[i], primes);
        f[x] += 1;
    }
    int ans = 0;
    set<integer> used;
    for (auto it : f) {
        integer x; int cnt; tie(x, cnt) = it;
        if (used.count(x)) continue;
        integer y = inv(x, primes);
        if (f.count(y)) {
            used.insert(y);
            ans += max(cnt, f[y]);
        } else {
            ans += cnt;
        }
    }
    if (f.count(1)) {
        ans -= f[1];
        ans += 1;
    }
    // output
    printf("%d\n", ans);
    return 0;
}
```
