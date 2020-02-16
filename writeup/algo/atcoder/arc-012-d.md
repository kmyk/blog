---
layout: post
alias: "/blog/2016/05/31/arc-012-d/"
date: 2016-05-31T22:08:49+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "prime", "combination" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc012/tasks/arc012_4" ]
---

# AtCoder Regular Contest 012 D - Don't worry. Be Together

$\Sigma$外すのも合成数への対処も解説を見ました。

## solution

まず、各人間の移動は独立である。
おのおのについて進み方の組み合わせが何通りか数えて掛け合わせればよい。

$t, m = \operatorname{modulo}$を固定する。
おのおのの出発地$(x,y)$に対し、組み合わせ$f(x,y)$を考える。
効いてくるのは距離だけなので、$f(x,y) = f(\|x\|, \|y\|)$。
$t \lt x + y$であれば時間内に原点に辿り着けないため$f(x, y) = 0$。
辿り着くだけでなく$t$秒後ちょうどに原点に居る必要があるので、$t - x - y \not\equiv 0 \pmod 2$なら$f(x, y) = 0$。
よって、$x, y \ge 0$としてよく、$x + y + 2u = t$となるように$u$をおける。

$t$個の時間を上下左右の4つに振り分ける。
下に$y$個、左に$x$個は確定している。
残る$2u$個の内$0 \le i \le u$個を左に振り分けると決めると、右にも$i$個、上下にもそれぞれ$u - i$個だと自動的に決まる。
つまり、$f(x,y) = \Sigma\_{i = 0}^u \frac{t}{(x + i)!i!(y + u - i)!(u - i)!}$である。
これをcombinationの形で書くとすると、下あるいは左に進むものは常に合計$x + y + u$個であることを使って、$f(x,y) = {}\_tc\_{x + y + u} \Sigma\_{i = 0}^u {}\_{x + y + u}C\_{x + i} \cdot {}\_uC_i$となる。
ここで、$\Sigma\_{i = 0}^u {}\_{x + y + u}C\_{x + i} \cdot {}\_uC_i = \Sigma\_{i = 0}^u {}\_{x + y + u}C\_{x + i} \cdot {}\_uC\_{u - i}$は、合計$t$個のものから$x + u$個選んでいるのと等しい。
よって、全体で$f(x,y) = {}\_tc\_{x + y + u} \cdot {}\_tc\_{x + u} = {}\_tc\_{u} \cdot {}\_tc\_{x + u}$となる。
$\Sigma$の除去に使った考察は${}\_{m+n}C_r = \Sigma\_{k = 0}^r {}\_mC_k \cdot {}\_nC\_{r-k}$などと一般化でき、
[Vandermonde's identity](https://en.wikipedia.org/wiki/Vandermonde%27s_identity)と呼ぶようである。

後は$\Pi_i f(x_i,y_i) \bmod m$を求めればよい。
${}\_nC_r = \frac{n!}{(n-r)!r!}$であるので、$m$が素数であれば単に階乗とその逆元を順に掛けていけばよい。
しかしこれは$m$が素数とは限らないためにそこまで単純ではない。

一般に、ちょうど$a$と$m$が互いに素であるときのみ$m$を法とする$a$の逆元が存在し、$a^{-1} \equiv a^{\phi(m) - 1} \pmod m$である。
$\phi$は[Euler's totient function](https://en.wikipedia.org/wiki/Euler%27s_totient_function)で、$m$が素数であれば$\phi(m) = m-1$。
つまり、$m$が合成数であるとき、$m$の($1$でない)約数には逆元がない。
逆元がない数を掛けて(さらに剰余を取って)しまうと、掛けた数が何であったかを覚えていても、元の掛けられた数が何であったかを復元できない。
一般の実数に$0$を掛けたときのように、情報が落ちてしまう。
よって、$m$が合成数であるとき、計算途中では掛け算を行ってはならない。

この問題は、逆数を計算しようとしなければ解決できる。$(a,k)$のようにして$a^k$を表現し、$k = -1$として逆数を持てばよい。
つまり、掛けられるべき階乗のそれぞれに関して、それを素因数分解した表現を取り回せばよい。

## 参考

-   <http://kmjp.hatenablog.jp/entry/2013/05/11/0900>
-   <http://rsujskf.blog32.fc2.com/blog-entry-2445.html>

## implementation

素因数分解libraryにバグがあった。最近混入したものか古いものかは分からない。

``` c++
#include <iostream>
#include <vector>
#include <map>
#include <tuple>
#include <functional>
#include <cmath>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define repeat_from_reverse(i,m,n) for (int i = (n)-1; (i) >= (m); --(i))
typedef long long ll;
using namespace std;

ll powi(ll x, ll y, ll p) {
    assert (y >= 0);
    x = (x % p + p) % p;
    ll z = 1;
    for (ll i = 1; i <= y; i <<= 1) {
        if (y & i) z = z * x % p;
        x = x * x % p;
    }
    return z;
}
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
map<int,int> factors(int n, vector<int> const & primes) {
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

int main() {
    int n, t, mod; cin >> n >> t >> mod;
    vector<int> facts(t+1);
    bool failed = false;
    auto choose = [&](int n, int r) {
        facts[n  ] += 1;
        facts[n-r] -= 1;
        facts[  r] -= 1;
    };
    repeat (i,n) {
        int x, y; cin >> x >> y;
        x = abs(x);
        y = abs(y);
        if  (t < x + y)           { failed = true; break; }
        if ((t - x - y) % 2 != 0) { failed = true; break; }
        ll u = (t - x - y) / 2;
        choose(t, u);
        choose(t, x + u);
    }
    ll ans;
    if (failed) {
        ans = 0;
    } else {
        vector<int> cnt(t+2);
        repeat_from_reverse (i,1,t+1) cnt[i] = cnt[i+1] + facts[i];
        vector<int> primes = sieve_of_eratosthenes(sqrt(t) + 100);
        map<int,int> ps;
        repeat_from (i,1,t+1) {
            for (auto it : factors(i, primes)) {
                int p, k; tie(p, k) = it;
                ps[p] += k * cnt[i];
            }
        }
        ans = 1;
        for (auto it : ps) {
            int p, cnt; tie(p, cnt) = it;
            assert (cnt >= 0);
            ans = ans * powi(p, cnt, mod) % mod;
        }
    }
    cout << ans << endl;
    return 0;
}
```
