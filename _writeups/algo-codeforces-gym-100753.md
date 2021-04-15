---
layout: post
redirect_from:
  - /writeup/algo/codeforces/gym-100753/
  - /blog/2016/02/01/cf-gym-100753/
date: 2016-02-01T04:09:20+09:00
tags: [ "competitive", "writeup", "codeforces", "icpc", "prime", "sieve-of-eratosthenes", "divisors", "miller-rabin" ]
---

# German Collegiate Programming Contest 2015 F. Divisions

## [F. Divisions](http://codeforces.com/gym/100753/attachments)

### 問題

整数$N \le 10^{18}$が与えられる。その約数の数$d(N)$を答えよ。

### 解法

まず準備として、
整数$n$が素数であるかの判定はmiller rabin素数判定法により$O(k \log n)$。
整数$n$以下の素数の列挙はeratosthenesの篩により$O(n \log \log n)$。

naiveに約数の数$d(n)$を計算するとすると、$n = {p_1}^{i_1} \cdot {p_2}^{i_2} \cdot \dots \cdot {p_l}^{i_l}$と素因数分解して、$d(n) = \Pi_k (i_k + 1)$。
しかしこれでは$O(\sqrt{n})$であり間に合わない。

$O(\sqrt[3]{n})$であれば間に合うので、これを目指す。
まず、$n = XY$で、$X$の素因数$p_i$は全て$\sqrt[3]{n}$以下$p_i \le \sqrt[3]{n}$、$Y$の素因数$q_i$は全て$\sqrt[3]{n}$超過$q_i \gt \sqrt[3]{n}$となるように分解する。
すると$X,Y$は互いに素であるので$d(n) = d(X)d(Y)$。
ここで$Y$の素因数を高々ふたつしか持たない。
つまり$Y = 1, p, p^2, pq$のいずれかである。

$\sqrt[3]{n}$以下の素数の全てで試し割りすれば、$X$及び$d(X)$は$O(\sqrt[3]{n})$で求まる。
これと同時に$Y$が(素因数へは分解できないが)求まる。
しかしここで$Y = 1$であれば$d(Y) = 1$、素数であれば$d(Y) = 2$、平方数であれば$Y = p^2$なので$d(Y) = 3$、そうでなければ$Y = pq$で$p,q$は互いに素なので$d(Y) = 4$と求まる。
これで$d(n) = d(X)d(Y)$が求まる。

### 参考

-   [Counting Divisors of a Number in  [tutorial] - Codeforces](http://codeforces.com/blog/entry/22317)
-   [Modular Multiplication Without Overflow \| Programming Praxis](http://programmingpraxis.com/2013/05/28/modular-multiplication-without-overflow/)

### 実装

`a * b % p`を`p * p`がoverflowするような場合でも計算できるやつとかもポイント。

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <random>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;

ll muli(ll a, ll b, ll p) { // safe against overflow
    assert (0 <= a and a < p);
    assert (0 <= b and b < p);
    ll c = 0;
    while (b > 0) {
        if (b % 2) c = p-c > a ? c+a : c+a-p; // c = (c + a) % p
        b /= 2;
        if (b)     a = p-a > a ? a+a : a+a-p; // a = (a + a) % p
    }
    return c;
}
ll powi(ll a, ll b, ll p) { // O(log b), safe against overflow
    assert (0 <= a and a < p);
    ll c = 1;
    for (ll e = a; b > 0; b /= 2) {
        if (b % 2) c = muli(c, e, p);
        e = muli(e, e, p);
    }
    return c;
}
template <class Generator>
bool is_prime(ll n, int iteration, Generator & gen) { // miller-rabin primality test, O(k log n)
    assert (0 <= n);
    if (n == 2) return true;
    if (n == 1 or n % 2 == 0) return false;
    const ll d = (n-1) >> __builtin_ctzll(n-1); // remove trailing zeros
    uniform_int_distribution<ll> dist(1,n-2); // [l,r]
    repeat (dummy,iteration) {
        ll a = dist(gen);
        ll t = d;
        ll y = powi(a,t,n);
        while (t != n-1 and y != 1 and y != n-1) {
            y = muli(y, y, n);
            t *= 2;
        }
        if (y != n-1 and t % 2 == 0) return false;
    }
    return true;
}
bool is_prime(ll n) {
    static default_random_engine engine = default_random_engine(random_device()());
    return is_prime(n, 20, engine);
}

vector<int> sieve_of_eratosthenes(int n) { // O(n log log n)
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

bool is_square(ll a) {
    ll b = sqrtl(a);
    return a == b*b;
}
int count_divisors(ll n, vector<int> const & primes) { // O(n^{1/3}), primes is in [2,n^{1/3}] inclusive
    int x = 1;
    for (int p : primes) {
        if (n < ll(p) * p * p) break;
        int i = 0;
        while (n % p == 0) { n /= p; ++ i; }
        x *= i + 1;
    }
    int y = n == 1 ? 1 : is_prime(n) ? 2 : is_square(n) ? 3 : 4; // here, n = 1, p, p^2 or pq
    return x * y;
}

int main() {
    ll n; cin >> n;
    vector<int> primes = sieve_of_eratosthenes(powl(n, 1/3.0)+1);
    cout << count_divisors(n, primes) << endl;
    return 0;
}
```
