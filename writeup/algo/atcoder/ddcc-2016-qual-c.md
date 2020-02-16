---
layout: post
alias: "/blog/2016/11/05/ddcc-2016-qual-c/"
date: "2016-11-05T22:26:13+09:00"
tags: [ "competitive", "writeup", "atcoder", "ddcc" ]
"target_url": [ "https://beta.atcoder.jp/contests/ddcc2016-qual/tasks/ddcc_2016_qual_c" ]
---

# DISCO presents ディスカバリーチャンネル コードコンテスト2016 予選: C - ロト2

これで通ると思うともっと簡単な解法が見えなくなるのやめたい。

## solution

$K$との$\mathrm{gcd}$で分類する。種類が十分減るので後は全ての組について試して数え上げれば間に合う。約数の数を$d(K)$として主に$O(d(K)^2)$になる。

$d(n)$や$\sigma_0(n)$と書かれるそれの増加速度はけっこうゆるやかなので問題ない: <https://en.wikipedia.org/wiki/Divisor_function>, <https://oeis.org/A000005>。

## implementation

$K = p_1^{i_1} p_2^{i_2} \dots p_n^{i_n}$と素因数分解して列$(i_1, i_2, \dots, i_n)$を持つような感じで書いた。そのようにする必要はなくて、整数としてそのまま持ってしまった方が楽。
割り切るかどうかを補集合との包含関係で見たりしたが、単に掛けて割るのでよかった。

``` c++
#include <iostream>
#include <vector>
#include <map>
#include <tuple>
#include <cmath>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
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
map<int,int> factorize(int n, vector<int> const & primes) {
    map<int,int> result;
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
int main() {
    int n; int k; cin >> n >> k;
    vector<int> a(n); repeat (i,n) cin >> a[i];
    map<int, int> ps = factorize(k, sieve_of_eratosthenes(sqrt(k) + 3));
    vector<int> primes; for (auto it : ps) primes.push_back(it.first);
    map<map<int, int>, int> qss;
    repeat (i,n) {
        map<int, int> qs;
        int b = a[i];
        for (int p : primes) {
            while (b % p == 0) {
                b /= p;
                qs[p] += 1;
            }
            setmin(qs[p], ps[p]);
        }
        qss[qs] += 1;
    }
    auto included = [&](map<int, int> & a, map<int, int> & b) {
        for (int p : primes) if (a[p] > b[p]) return false;
        return true;
    };
    ll ans = 0;
    for (auto it1 : qss) {
        map<int, int> qs; int cnt1; tie(qs, cnt1) = it1;
        map<int, int> rs; for (int p : primes) rs[p] = ps[p] - qs[p];
        for (auto it2 : qss) {
            map<int, int> ss; int cnt2; tie(ss, cnt2) = it2;
            if (included(rs, ss)) {
                if (qs == ss) {
                    ans += cnt1 *(ll) (cnt2 - 1);
                } else {
                    ans += cnt1 *(ll) cnt2;
                }
            }
        }
    }
    assert (ans % 2 == 0);
    cout << ans / 2 << endl;
    return 0;
}
```
