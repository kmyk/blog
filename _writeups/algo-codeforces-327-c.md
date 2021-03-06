---
layout: post
redirect_from:
  - /writeup/algo/codeforces/327-c/
  - /blog/2015/12/17/cf-327-c/
date: 2015-12-17T23:54:20+09:00
tags: [ "competitive", "writeup", "codeforces", "math" ]
"target_url": [ "!-- more --" ]
---

# Codeforces Round #191 (Div. 2) C. Magic Five

## [C. Magic Five](http://codeforces.com/contest/327/problem/C) {#c}

### 問題

数字のみからなる文字列$a$ ($\|a\| \le 10^5$)と整数$k$($k \le 10^9$)が与えられる。$a$の$k$回の繰り返しで表現される文字列を$s$とする。$s$中の文字を任意に削除して$5$で割り切れる数字を表す文字列を作る。このような削除の方法は何通りあるか。先頭に`0`を残すことは許容されるが、空文字列を作るのは禁止である。

### 解法

削除後の文字列の末尾は`0`か`5`である。
このため、末尾に持ってくる文字の出現を決めれば、そのような削除の仕方は、その文字より手前にある文字の数$i$に対し$2^i$である。
これを、$s$が$a$の繰り返しで表現されるという性質を用いて高速に計算する。

$a$中の位置$i$に`0`あるいは`5`が出現したとき、$s$中の$i, i+|a|, i+2|a|, \dots, i+(k-1)|a|$にも同じ数字が出現する。それらを合わせると$2^i + 2^{i+|a|} + 2^{i+2|a|} + \dots + 2^{i+(k-1)|a|}$通りの削除の方法がある。これは$2^i \cdot ( 1 + 2^{|a|} + 2^{2|a|} + \dots + 2^{(k-1)|a|} ) = 2^i \cdot \frac{2^{k|a|} - 1}{2^{|a|} - 1}$と変形できる。
これを$a$中の`0` `5`全てに関して足し合わせればよい。

### 実装

``` c++
#include <iostream>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
constexpr ll mod = 1000000007;
using namespace std;
ll powi(ll a, ll b, ll p) {
    ll result = 1;
    ll e = a;
    for (int i = 0; (1ll << i) <= b; ++ i) {
        if ((1ll << i) & b) {
            result = result * e % p;
        }
        e = e * e % p;
    }
    return result;
}
ll inv(ll x, ll p) { // inv library, ver 2015.12.17
    x = (x % mod + mod) % mod;
    ll y = 1;
    for (int i = 0; (1 << i) <= p - 2; ++ i) {
        if ((p - 2) & (1 << i)) {
            y = y * x % p;
        }
        x = x * x % p;
    }
    return y;
}
int main() {
    string a; ll k; cin >> a >> k;
    ll l = a.size();
    ll e = powi(2, l, mod);
    ll t = (powi(e, k, mod) - 1) * inv(e - 1, mod) % mod;
    ll result = 0;
    repeat (i,a.length()) if (a[i] == '0' or a[i] == '5') {
        result += t * powi(2, i, mod) % mod;
        result %= mod;
    }
    cout << result << endl;
    return 0;
}
```
