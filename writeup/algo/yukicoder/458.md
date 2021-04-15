---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/458/
  - /blog/2016/12/09/yuki-458/
date: "2016-12-09T23:00:04+09:00"
tags: [ "competitive", "writeup", "yukicoder", "dp", "prime-number" ]
"target_url": [ "http://yukicoder.me/problems/no/458" ]
---

# Yukicoder No.458 異なる素数の和

## solution

普通にDP。素数定理$\pi(x) \approx \frac{x}{\log x}$より、$O(\frac{N^2}{\log N})$か。

## implementation

``` c++
#include <iostream>
#include <vector>
#define repeat_reverse(i,n) for (int i = (n)-1; (i) >= 0; --(i))
using namespace std;
template <class T> void setmax(T & a, T const & b) { if (a < b) a = b; }
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
int main() {
    int n; cin >> n;
    vector<int> primes = sieve_of_eratosthenes(n);
    vector<int> dp(n+1, -1);
    dp[0] = 0;
    for (int p : primes) {
        repeat_reverse (i,n) if (dp[i] != -1 and i+p < n+1) {
            setmax(dp[i+p], dp[i]+1);
        }
    }
    cout << dp[n] << endl;
    return 0;
}
```
