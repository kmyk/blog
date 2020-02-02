---
layout: post
alias: "/blog/2016/09/27/srm-699-easy/"
date: "2016-09-27T01:43:26+09:00"
title: "TopCoder SRM 699 Div1 Easy: OthersXor"
tags: [ "competitive", "writeup", "topcoder", "srm", "dp" ]
---

I've got AC, but it's too slow and my rating didn't increase too much.

## solution

Do bitwisely. $O(N)$.

Let the given nonnegative numbers be $x_0, x_1, \dots, x\_{k-1}$, and there are $n-k$ masked numbers.
Let the actual numbers be $a_0, a_1, \dots, a\_{k-1}, \dots, a\_{n-1}$ and $X$ be the xor-sum of them, then there are $k$ equations: $$ \begin{array}{ll}
    a_i = X \oplus x_i  & (i \lt k)
\end{array} $$.
The definition of $X$ is: $$
    X = \Sigma^{\oplus}\_i a_i
$$.

Assuming $a_k, \dots, a\_{n-1}$ are $0$,
the sum of $x_i$ makes $X$, $$ \begin{array}{ll}
    a_0 \oplus a_1 \oplus \dots \oplus a\_{k-1} = X = x_0 \oplus x_1 \oplus \dots \oplus x\_{k-1} & (k \; \text{is even}) \\\\
    a_0 \oplus a_1 \oplus \dots \oplus a\_{k-1} = X = x_0 \oplus x_1 \oplus \dots \oplus x\_{k-1} \oplus X & (k \; \text{is odd})
\end{array} $$.
In the case that $k$ is even, the $X$ is fixed and you can compute the answer.
In the case that $k$ is odd, if the $x_0 \oplus x_1 \oplus \dots \oplus x\_{k-1}$ is $0$ then $X$ is arbitrary. Otherwise, contradiction.
But also, if you have $x_k$, a number which has no constraint, you can use this to make $X$ arbitrary.

Let think about deciding the free $X$ (without $a_k$, and with $a_k$).
When $a_k$ is not used, bitwisely do. Count $1$s of the $i$-th bit of $x_k$, and define the $i$-th bit of $X$ according to the result.
When $a_k$ is used, do almost same thing, but you sholud take care about how to decide the $x_k$.

## implementation

``` c++
#include <bits/stdc++.h>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) y) { return (f)(begin(y), end(y), ## __VA_ARGS__); })(x)
typedef long long ll;
template <class T> void setmin(T & a, T const & b) { if (b < a) a = b; }
using namespace std;
class OthersXor { public: long long minSum(vector<int>); };

const ll inf = ll(1e18)+9;
long long OthersXor::minSum(vector<int> xs) {
    int n = xs.size();
    xs.erase(whole(remove, xs, -1), xs.end());
    auto foo = [&](ll sum) {
        ll acc = 0;
        for (int x : xs) acc += sum ^ x;
        return acc;
    };
    auto bar = [&]() {
        vector<int> cnt(32);
        for (int x : xs) {
            repeat (i, cnt.size()) {
                cnt[i] += (x & (1ll<<i)) != 0;
            }
        }
        ll acc = 0;
        repeat (i, cnt.size()) {
            if (cnt[i] > xs.size()/2) {
                acc |= 1ll<<i;
            }
        }
        return acc;
    };
    ll ans = inf;
    ll sum_x = whole(accumulate, xs, 0ll, bit_xor<ll>());
    if (xs.size() % 2 == 0) {
        setmin(ans, foo(sum_x));
        if (xs.size() < n) {
            xs.push_back(sum_x);
            setmin(ans, foo(bar()));
            xs.pop_back();
        }
    } else {
        if (sum_x == 0) {
            setmin(ans, foo(bar()));
        }
        if (xs.size() < n) {
            ll sum = bar();
            xs.push_back(sum ^ sum_x);
            setmin(ans, foo(sum));
            xs.pop_back();
        }
    }
    if (ans == inf) ans = -1;
    return ans;
}
```
