---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/28/
  - /blog/2017/01/06/yuki-28/
date: "2017-01-06T15:26:28+09:00"
tags: [ "competitive", "writeup", "yukicoder" ]
"target_url": [ "http://yukicoder.me/problems/no/28" ]
---

# Yukicoder No.28 末尾最適化

嘘のつもりで投げたら通り、実は正しい解法だった。だめ。

## solution

$B$の素因数のどれがボトルネックになるか全部試す。$O(Q \cdot ( N_i\log N_i + B \log \log B))$。

$B = p_1^{k_1}p_2^{k_2}\dots p_l^{k_l}$とする。
$T = p_1^{k_1'}p_2^{k_2'}\dots p_l^{k_l'}R$としたとき、末尾の$0$の数$\mathrm{cnt} = \min_i \lfloor \frac{k_i'}{k_i} \rfloor$。
この$j = \operatorname{argmin}\_i \lfloor \frac{k_i'}{k_i} \rfloor$を決め打ちすれば、$X$を(他の素数を考慮せず)単に$p_j$の指数の小さい方から$K$個掛け合わせて$T$とすればよくなる。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <map>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using ll = long long;
using namespace std;
template <class T> void setmin(T & a, T const & b) { if (b < a) a = b; }
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
const int inf = 1e9+7;
int main() {
    int q; cin >> q;
    while (q --) {
        int seed, n, k, b; cin >> seed >> n >> k >> b;
        map<int,int> ps = prime_factrorize(b, sieve_of_eratosthenes(b));
        vector<vector<int> > xs;
        for (int x = seed; xs.size() < n+1; x = x *(ll) (x + 12345) % 100000009 + 1) {
            int y = x;
            xs.emplace_back();
            for (auto it : ps) {
                int p = it.first;
                xs.back().push_back(0);
                while (y % p == 0) { ++ xs.back().back(); y /= p; }
            }
        }
        int ans = inf;
        repeat (p,ps.size()) {
            partial_sort(xs.begin(), xs.begin() + k, xs.end(), [&](vector<int> const & x, vector<int> const & y) { return x[p] < y[p]; });
            vector<int> t(ps.size());
            repeat (i,k) repeat (j,ps.size()) t[j] += xs[i][j];
            int j = 0;
            for (auto it : ps) {
                int cnt = it.second;
                setmin(ans, t[j] / cnt);
                ++ j;
            }
        }
        cout << ans << endl;
    }
    return 0;
}
```
