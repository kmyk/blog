---
redirect_from:
  - /writeup/algo/yukicoder/726/
layout: post
date: 2018-08-25T19:00:56+09:00
tags: [ "competitive", "writeup", "yukicoder", "prime-numer", "game" ]
"target_url": [ "https://yukicoder.me/problems/no/726" ]
---

# Yukicoder No.726 Tree Game

## 解法

コーナーケースがとてもつらいが、愚直にやれば通る。
ゲームの性質から(選べるなら)上と右のどちらを選んでも同じことに気付けばよい。
$N = \max ( X, Y )$ と$N$付近での素数の間隔 $\Delta(N)$ を置いて $(\sqrt{N} \Delta(N))$ になる。
素数はけっこう密に存在する。

## メモ

$7$WA

## 実装

``` c++
#include <bits/stdc++.h>
using ll = long long;
using namespace std;

vector<int> list_primes(int n) {
    vector<bool> is_prime(n, true);
    is_prime[0] = is_prime[1] = false;
    for (int i = 2; i *(ll) i < n; ++ i)
        if (is_prime[i])
            for (int k = 2 * i; k < n; k += i)
                is_prime[k] = false;
    vector<int> primes;
    for (int i = 2; i < n; ++ i)
        if (is_prime[i])
            primes.push_back(i);
    return primes;
}
bool is_prime(ll n, vector<int> const & primes) {
    if (n == 1) return false;
    for (int p : primes) {
        if (n < (ll)p * p) break;
        if (n % p == 0) return false;
    }
    return true;
}

const auto primes = list_primes(1e5);
bool solve(int y, int x) {
    bool a = not is_prime(y + 1, primes) and not is_prime(x, primes);
    bool b = not is_prime(y, primes) and not is_prime(x + 1, primes);
    if (a) {
        return not solve(y + 1, x);
    } else if (b) {
        return not solve(y, x + 1);
    } else {
        return false;
    }
}

int main() {
    int y, x; cin >> y >> x;
    cout << (solve(y, x) ? "First" : "Second") << endl;
    return 0;
}
```
