---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc_052_d/
  - /writeup/algo/atcoder/arc-052-d/
  - /blog/2016/05/16/arc-052-d/
date: 2016-05-16T00:16:21+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "dp", "meet-in-the-middle" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc052/tasks/arc052_d" ]
---

# AtCoder Regular Contest 052 D - 9

独力で解けると楽しい。

## solution

桁DP。半分全列挙。$O(\sqrt{M})$。

整数$n$が$9$っぽい$\phi(n)$とは、$\Sigma_i n_i \equiv n \pmod K$のちょうどそのとき。ただし$n_i$は$n$の$10$進数展開の下から$i$桁目($0$-based)の数字。
$n = \Sigma_i n_i \cdot 10^i$であるので、$\phi(n) \iff \Sigma_i n_i \cdot (10^i - 1) \equiv 0 \pmod K$と変形できる。
よって、各桁に重み$(10^i - 1) \bmod K$が乗っているときに、重みが$0$になるような桁の取り方の総数を求める問題として理解できる。

ここで、半分全列挙が使える。上位の桁と下位の桁でそれぞれ可能な重みの総和とその数を数え、対応を取る。
桁の選び方は基本的に独立であるので基本的に可能だが、$n \le M$であるという制限は考慮する必要がある。
この制約により実装が多少面倒になるが、それだけである。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <unordered_map>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_reverse(i,n) for (int i = (n)-1; (i) >= 0; --(i))
#define repeat_from_reverse(i,m,n) for (int i = (n)-1; (i) >= (m); --(i))
typedef long long ll;
using namespace std;
bool is_nine_like(ll n, ll k) {
    ll x = n % k;
    ll y = 0; for (; n; n /= 10) y = (y + n % 10) % k;
    return x == y;
}
unordered_map<ll,ll> update(unordered_map<ll,ll> const & xs, ll e, ll k, int ten) {
    unordered_map<ll,ll> nxs;
    for (auto it : xs) {
        ll x, cnt; tie(x, cnt) = it;
        repeat (d,ten) {
            nxs[(x + d * e) % k] += cnt;
        }
    }
    return nxs;
}
ll product(unordered_map<ll,ll> const & xs, unordered_map<ll,ll> const & ys, ll acc, ll k) {
    ll cnt = 0;
    for (auto it : xs) {
        ll x, xcnt; tie(x, xcnt) = it;
        ll y = - (acc + x); y = (y % k + k) % k;
        if (ys.count(y)) {
            ll ycnt = ys.at(y);
            cnt += xcnt * ycnt;
        }
    }
    return cnt;
}
int main() {
    // input
    ll k; string s; cin >> k >> s;
    ll m = stoll(s);
    // prepare
    vector<ll> e; // e_i = 10^i
    for (ll it = 1; it <= m; it *= 10) e.push_back(it % k - 1);
    int r = e.size();
    int l = r/2;
    // enumerate
    vector<unordered_map<ll,ll> > xss(l+1); // lower
    xss[0][0] = 1;
    repeat (i,l) xss[i+1] = update(xss[i], e[i], k, 10);
    vector<unordered_map<ll,ll> > yss(r-l+1); // upper
    yss[0][0] = 1;
    repeat (i,r-l) yss[i+1] = update(yss[i], e[l+i], k, 10);
    // count
    ll ans = 0;
    ll acc = 0;
    repeat_from_reverse (i,l,r) {
        unordered_map<ll,ll> zs = update(yss[i-l], e[i], k, s[r-i-1]-'0');
        ans += product(xss.back(), zs, acc, k);
        acc = (acc + (s[r-i-1]-'0') * e[i]) % k;
    }
    repeat_reverse (i,l) {
        unordered_map<ll,ll> zs = update(xss[i], e[i], k, s[r-i-1]-'0');
        ans += zs[((- acc) % k + k) % k];
        acc = (acc + (s[r-i-1]-'0') * e[i]) % k;
    }
    // adjust
    ans -= 1; // for 0
    if (is_nine_like(m, k)) ans += 1; // for m itself
    // output
    cout << ans << endl;
    return 0;
}
```
