---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/2/
  - /blog/2016/09/13/yuki-2/
date: "2016-09-13T23:18:28+09:00"
tags: [ "competitive", "writeup", "yukicoder", "game", "prime", "nim", "grandy" ]
"target_url": [ "http://yukicoder.me/problems/no/2" ]
---

# Yukicoder No.2 素因数ゲーム

各素因数がnimの山になっていて、その指数が石の数なので、素因数分解を$1$度するだけでよい。

$0$から$N$までそれぞれ$\mathrm{mex}$でgrandy数をDPで求めてTLEしていた。
必要なのはその内の$\log N$個ぐらいではということで再帰にしたら通った。
頭付いてなかった。寝起きにしてもひどい。

``` c++
#include <iostream>
#include <vector>
#include <set>
#include <map>
#include <tuple>
#include <cmath>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;

vector<int> sieve_of_eratosthenes(int n) { // enumerate primes in [2,n] with O(n log log n)
    vector<bool> is_prime(n+1, true);
    is_prime[0] = is_prime[1] = false;
    for (int i = 2; i*i <= n; ++ i)
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
        if (n < p *(int) p) break;
        while (n % p == 0) {
            result[p] += 1;
            n /= p;
        }
    }
    if (n != 1) result[n] += 1;
    return result;
}
template <typename C>
int mex(C const & xs) {
    int y = 0;
    for (int x : xs) { // xs must be sorted (duplication is permitted)
        if (y <  x) break;
        if (y == x) ++ y;
    }
    return y;
}

int grandy(int n, vector<int> const & primes, map<int,int> & memo) {
    if (n <= 1) return 0;
    if (memo.count(n)) return memo[n];
    set<int> g;
    for (auto it : factors(n, primes)) {
        int p, cnt; tie(p, cnt) = it;
        int m = n;
        repeat (i,cnt) {
            m /= p;
            g.insert(grandy(m, primes, memo));
        }
    }
    return memo[n] = mex(g);
}
int main() {
    int n; cin >> n;
    vector<int> primes = sieve_of_eratosthenes(sqrt(n) + 3);
    map<int,int> memo;
    cout << (grandy(n, primes, memo) ? "Alice" : "Bob") << endl;
    return 0;
}
```
