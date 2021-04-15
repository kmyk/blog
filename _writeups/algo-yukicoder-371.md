---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/371/
  - /blog/2016/05/24/yuki-371/
date: 2016-05-24T20:51:40+09:00
tags: [ "competitive", "writeup", "yukicoder", "lie" ]
"target_url": [ "http://yukicoder.me/problems/980" ]
---

# Yukicoder No.371 ぼく悪いプライムじゃないよ

なんだか嘘っぽさはあるが、嘘ではない気がする。

## solution

適当にする。定数倍大きめの$O(\sqrt{H})$。

目的の合成数$c$の素因数の数を考える。
基本的には$2$で、特に$c = p^2$や$c = p \cdot (p + 3)$といった形をしていることが多そうである。
そこで、$p \le \sqrt{H}$となるような最大の素数$p$に対し、$p^2, p (p + 1), p (p + 2), \dots$を調べていけばよさそうである。
$L \le p^2 \le H$となるような素数$p$が存在する場合にはこれで上手くいく。

しかし実際は、$L = H = p \cdot q \cdot r$のような場合等もある。
このような場合は$[L,H]$の範囲を全探索する、というのが思い付く。
$[L,H]$の幅が小さければこれでよい。

$L \le p^2 \le H$である素数$p$がない場合でも、$[L,H]$の幅は最大で$10^6$規模となる。
調べきれない場合は存在する。
しかし、そのような場合だけを考えるとすると、$[L,H]$の幅が十分大きいことを仮定に追加できる。
これは、$p^2$の形はしていないにしても、目的の合成数の素因数の数が$2$であるらしいということを導く。
そこで、$i$番目の素数と$i,i+1,\dots,i+100$番目の素数との積を全て試せば通ってしまう。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <cmath>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define repeat_reverse(i,n) for (int i = (n)-1; (i) >= 0; --(i))
typedef long long ll;
template <class T> bool setmax(T & l, T const & r) { if (not (l < r)) return false; l = r; return true; }
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

vector<ll> factors(ll n, vector<int> const & primes) {
    vector<ll> result;
    for (ll p : primes) {
        if (n < p * p) break;
        while (n % p == 0) {
            result.push_back(p);
            n /= p;
        }
    }
    if (n != 1) result.push_back(n);
    return result;
}

int main() {
    ll l, h; cin >> l >> h; // [l, h]
    vector<int> primes = sieve_of_eratosthenes(sqrt(h) * 10);
    pair<ll,ll> ans = { -1, -1 };
    repeat_reverse (i,primes.size()) {
        ll p = primes[i];
        repeat_from (j,i,min<int>(i+1000,primes.size())) {
            ll q = primes[j];
            if (l <= p * q and p * q <= h) {
                setmax(ans, make_pair(p, p * q));
            }
        }
        if (ans.second != -1) break;
    }
    if (ans.second == -1 or h - l + 1 < 10000) {
        for (ll n = l; n < h+1; ++ n) {
            vector<ll> fs = factors(n, primes);
            if (fs.size() != 1) {
                setmax(ans, make_pair(fs.front(), n));
            }
        }
    }
    cout << ans.second << endl;
    return 0;
}
```

---

# Yukicoder No.371 ぼく悪いプライムじゃないよ

-   Sun Jun  5 19:24:31 JST 2016
    -   落とされたので調整した
    -   `repeat_from (j,i,min<int>(i+100,primes.size())) { ... }` を
    -   `repeat_from (j,i,min<int>(i+1000,primes.size())) { ... }` に
