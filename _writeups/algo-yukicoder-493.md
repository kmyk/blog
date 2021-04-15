---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/493/
  - /blog/2017/03/11/yuki-493/
date: "2017-03-11T17:28:57+09:00"
tags: [ "competitive", "writeup", "yukicoder" ]
"target_url": [ "http://yukicoder.me/problems/no/493" ]
---

# Yukicoder No.493 とても長い数列と文字列(Long Long Sequence and a String)

長さが指数で増えるのに気付かなかった。
その後は丁寧にやるだけだったが、バグを埋めやすい感じがあった。

## solution

文字列$f(K)$の長さは指数で増えるので$K \le 64$。binary indexed treeのように端から取っていく。$O(\log R)$。

和と$10^9+7$を法とする積は可逆であるので($1$-basedで)$L = 1$として$2$回求めて差を取ればよい。$L = 1$とする。

見る必要のある各$f(K)$についてその中での和と積を求めておいて、左端から取っていくことを考える。
$k$を$K$から$1$まで減らしながら、$\mathrm{len}(\mathrm{str}(f(k)) \oplus \mathrm{str}(k^2)) \le R$なら$R \gets R - \mathrm{len}(\mathrm{str}(f(k)) \oplus \mathrm{str}(k^2))$とする、などとする。
真ん中に$\mathrm{str}(k^2)$が挟まってるので面倒だが、基本はdoublingとかの感じで。

イメージ図 $(K, L, R) = (5, 1, 26)$:

```
L                        R
1419141161419141
                25
                  1419141
                         1
                          --------
```

## implementation

``` c++
#include <iostream>
#include <vector>
#include <sstream>
#include <functional>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < int(n); ++(i))
using ll = long long;
using namespace std;
template <class T> inline void setmin(T & a, T const & b) { a = min(a, b); }

ll powmod(ll x, ll y, ll p) { // O(log y)
    assert (y >= 0);
    x %= p; if (x < 0) x += p;
    ll z = 1;
    for (ll i = 1; i <= y; i <<= 1) {
        if (y & i) z = z * x % p;
        x = x * x % p;
    }
    return z;
}
ll inv(ll x, ll p) { // p must be a prime, O(log p)
    assert ((x % p + p) % p != 0);
    return powmod(x, p-2, p);
}

constexpr int mod = 1e9+7;
pair<ll, int> from_string(string const & s) {
    ll sum = 0;
    int prod = 1;
    for (char c : s) {
        int d = (c == '0' ? 10 : c - '0');
        sum += d;
        prod = prod *(ll) d % mod;
    }
    return { sum, prod };
}
pair<ll, int> addmul(pair<ll, int> a, pair<ll, int> b) {
    return { a.first + b.first, a.second *(ll) b.second % mod };
}
int main() {
    int k; ll l, r; cin >> k >> l >> r; -- l;
    vector<string> str { "" };
    vector<ll> width { 0 };
    vector<ll> sums { 0 };
    vector<int> prods { 1 };
    repeat_from (i,1,k+1) {
        ostringstream oss;
        oss << i*i;
        string s = oss.str();
        str.push_back(s);
        width.push_back(2 * width.back() + s.length());
        ll sum = 2 * sums.back();
        int prod = prods.back() *(ll) prods.back() % mod;
        tie(sum, prod) = addmul(make_pair(sum, prod), from_string(s));
        sums.push_back(sum);
        prods.push_back(prod);
        if (r <= width.back()) break;
    }
    function<pair<ll, int> (int, ll)> func = [&](int i, ll r) { // in the string f(i), accumulate of [0, r)
        if (i == 0) { // exit
            return make_pair(0ll, 1);
        } else if (r < width[i-1]) { // go left
            return func(i-1, r);
        } else if (r == width[i-1]) { // left
            return make_pair(sums[i-1], prods[i-1]);
        } else if (r < width[i-1] + str[i].length()) { // left + use center
            ll sum = sums[i-1];
            int prod = prods[i-1];
            string s = str[i].substr(0, r - width[i-1]);
            return addmul(make_pair(sum, prod), from_string(s));
        } else { // left + center, go right
            assert (r < width[i-1] + str[i].length() + width[i-1]);
            ll sum = sums[i-1];
            int prod = prods[i-1];
            string s = str[i];
            ll nr = r - width[i-1] - s.length();
            return addmul(addmul(make_pair(sum, prod), from_string(s)), func(i-1, nr));
        }
    };
    if (width.back() < r) {
        cout << -1 << endl;
    } else {
        ll lsum; int lprod; tie(lsum, lprod) = func(width.size(), l);
        ll rsum; int rprod; tie(rsum, rprod) = func(width.size(), r);
        cout << (rsum - lsum) << ' ' << (rprod *(ll) inv(lprod, mod) % mod) << endl;
    }
    return 0;
}
```
