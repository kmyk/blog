---
layout: post
redirect_from:
  - /writeup/algo/atcoder/code-festival-2016-final-e/
  - /blog/2016/12/24/code-festival-2016-final-e/
date: "2016-12-24T19:57:43+09:00"
tags: [ "competitive", "writeup", "atcoder", "codefestival", "binary-search" ]
"target_url": [ "https://beta.atcoder.jp/contests/cf16-final-open/tasks/codefestival_2016_final_e" ]
---

# CODE FESTIVAL 2016 Final: E - Cookies

少ない種類に上手く場合分けして尽くすやつ。
本番では嘘が混ったメモ化再帰で無理矢理に部分点を奪った。

## solution

クッキーを食べる回数を総当たり。$O((\log N)^2)$。

クッキーを食べる回数$k$を固定する。次の議論から$k$は$\log N$ぐらいまで見れば十分。
開始/前回食べてから次に食べる/$N$枚用意するまでの時間を$s_0, s_1, s_2, \dots, s_k$とすると、最後の時刻($t = Ak + \sum_i s_i$)に焼き上がっているのは$\prod_i s_i$枚。
例えば$(s - 1)(s + 1) = s^2 - 1 \lt s^2$であるように、$s_0, s_1, s_2, \dots, s_k$は均一な方が有利。つまり$\max_i s_i - \min_i s_i \le 1$が言える。
$k$を固定したときこのような$\min_i s_i$は二分探索で求められる。
$s_0, s_1, s_2, \dots, s_k$中のいくつかは$\min_i s_i + 1$であるが、それがいくつかは$k$回試せばよい。

## implementation

``` c++
#include <iostream>
#include <cmath>
#include <cassert>
typedef long long ll;
using namespace std;
template <class T> void setmin(T & a, T const & b) { if (b < a) a = b; }
const ll inf = 1e18+9;
int main() {
    ll n, a; cin >> n >> a;
    ll ans = inf;
    for (int k = 1; ; ++ k) {
        ll l = 0, r = n;
        while (l + 1 < r) {
            ll m = (l + r) / 2;
            (pow(m, k) < n ? l : r) = m;
        }
        assert (pow(l, k)  < n);
        assert (pow(r, k) >= n);
        int m = 0; while (pow(l,k-m) * pow(r,m) < n) ++ m;
        setmin(ans, l*k+m + a*(k-1));
        if (l <= 1) break;
    }
    cout << ans << endl;
    return 0;
}
```
