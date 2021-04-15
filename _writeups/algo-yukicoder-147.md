---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/147/
  - /blog/2016/02/27/yuki-147/
date: 2016-02-27T11:32:25+09:00
tags: [ "competitive", "writeup", "yukicoder", "fibonacci", "matrix" ]
"target_url": [ "http://yukicoder.me/problems/370" ]
---

# Yukicoder No.147 試験監督（2）

$10$進数字列で累乗とか書きたくないからpythonに逃げるもTLEしc++に戻され、行列累乗書くの面倒なので$F_n = F\_{\lfloor \frac{n}{2} \rfloor} F\_{\lceil \frac{n}{2} \rceil} + F\_{\lfloor \frac{n}{2} \rfloor - 1} F\_{\lceil \frac{n}{2} \rceil - 1}$[^1]をやってみたら(1ケース5秒なら通ってたんだろうけど)速度が足りなくて、結局まじめに全部書くはめになった。

## No.147 試験監督（2）

### 解法

${\rm ans} = \Pi_i {\rm fib}(C_i)^D_i$。繰り返し二乗法。$O(N (\log C + \log D))$。

机ごとに座り方は区別するので、それぞれの種類の机ひとつに関して座り方が何通りか求め、これをその個数乗すればよい。
座り方が何通りかはfibonacci数になっている。実験する、あるいは漸化式を立てれば見える。

### 実装

TLEが厳しい。

``` c++
#include <iostream>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_reverse(i,n) for (int i = (n)-1; (i) >= 0; --(i))
typedef long long ll;
using namespace std;
const int mod = 1e9+7;
vector<vector<ll> > operator * (vector<vector<ll> > const & p, vector<vector<ll> > const & q) {
    int n = p.size();
    vector<vector<ll> > r(n, vector<ll>(n));
    repeat (y,n) {
        repeat (z,n) {
            repeat (x,n) {
                r[y][x] += p[y][z] * q[z][x] % mod;
                r[y][x] %= mod;
            }
        }
    }
    return r;
}
ll fib(ll n) {
    vector<vector<ll> > f(2, vector<ll>(2));
    vector<vector<ll> > e(2, vector<ll>(2));
    f[0][0] = f[1][1] = 1;
    e[0][0] = e[0][1] = e[1][0] = 1;
    for (ll i = 1; i <= n; i <<= 1) {
        if (n & i) f = f * e;
        e = e * e;
    }
    return f[0][0];
}
int powi(int x, string const & d) {
    ll y = 1;
    int n = d.size();
    repeat_reverse (i,n) {
        int c = d[i] - '0';
        ll z = 1;
        repeat (j,10) {
            if (j == c) y = y * z % mod;
            z = z * x % mod;
        }
        x = z;
    }
    return y;
}
int main() {
    int n; cin >> n;
    ll ans = 1;
    repeat (i,n) {
        ll c; string d; cin >> c >> d;
        ans = ans * powi(fib(c+1), d) % mod;
    }
    cout << ans << endl;
    return 0;
}
```

<hr>

[^1]: <https://en.wikipedia.org/wiki/Fibonacci_number>
