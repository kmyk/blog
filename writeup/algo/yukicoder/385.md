---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/385/
  - /blog/2016/07/02/yuki-385/
date: 2016-07-02T00:23:18+09:00
tags: [ "competitive", "writeup", "yukicoder", "dp", "sieve-of-eratosthenes", "prime" ]
"target_url": [ "http://yukicoder.me/problems/no/385" ]
---

# Yukicoder No.385 カップ麺生活

## solution

普通にDP。$i$円使ったときに買えるカップ麺の数$\mathrm{dp}\_j$を全て求めれて適当に足し合わせればよい。
$O(MN + M \log \log M)$。

## implementation

素数かどうか判定すべきなのは「残り所持金」であることに注意。

``` c++
#include <cstdio>
#include <vector>
#include <algorithm>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) y) { return (f)(begin(y), end(y), ## __VA_ARGS__); })(x)
using namespace std;
template <class T> void setmax(T & a, T const & b) { if (a < b) a = b; }

vector<bool> sieve_of_eratosthenes(int n) { // enumerate primes in [2,n] with O(n log log n)
    vector<bool> is_prime(n+1, true);
    is_prime[0] = is_prime[1] = false;
    for (int i = 2; i*i <= n; ++i)
        if (is_prime[i])
            for (int k = i+i; k <= n; k += i)
                is_prime[k] = false;
    return is_prime;
}

int main() {
    // input
    int m, n; scanf("%d%d", &m, &n);
    vector<int> cs(n); repeat (i,n) scanf("%d", &cs[i]);
    // compute
    vector<int> dp(m+1);
    dp[0] = 0;
    repeat (i,m+1) {
        for (int c : cs) if (i-c >= 0) {
            if (i-c == 0 or dp[i-c] >= 1) {
                setmax(dp[i], dp[i-c] + 1);
            }
        }
    }
    int ans = 0;
    vector<bool> is_prime = sieve_of_eratosthenes(m+1);
    repeat (i,m+1) if (is_prime[m-i]) ans += dp[i];
    ans += *whole(max_element, dp);
    // output
    printf("%d\n", ans);
    return 0;
}
```
