---
layout: post
alias: "/blog/2015/12/24/xmascontest-2015-a/"
date: 2015-12-24T22:55:13+09:00
tags: [ "competitive", "writeup", "atcoder", "matrix" ]
---

# Xmas Contest 2015 A - Accumulation

行列累乗法の例題のような素直な問題。

## [A - Accumulation](https://beta.atcoder.jp/contests/xmascontest2015/tasks/xmascontest2015_a) {#a}

### 解法

行列累乗法 $O(\log T + N)$


疑似コードの最終行

```
    X=(A*X+B) mod C
```

は線形な演算なので、$$
\left(
\begin{matrix}
X' \\
1 \\
\end{matrix}
\right) = \left(
\begin{matrix}
A & B \\
0 & 1 \\
\end{matrix}
\right) \left(
\begin{matrix}
X \\
1 \\
\end{matrix}
\right)
\pmod C
$$と書ける。ここで、$$
\left(
\begin{matrix}
X' \\
1 \\
\end{matrix}
\right) = \left(
\begin{matrix}
A & B \\
0 & 1 \\
\end{matrix}
\right)^T \left(
\begin{matrix}
X \\
1 \\
\end{matrix}
\right)
\pmod C
$$とすれば、この演算を$T$回まとめて行うことができる。
この行列の$T$乗を事前に$O(\log T)$で計算しておけばよい。

### 実装

``` c++
#include <iostream>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;
void mul(ll (& dest)[2][2], ll (& a)[2][2], ll (& b)[2][2], ll c) {
    ll t[2][2] = {};
    repeat (y,2) repeat (z,2) repeat (x,2) {
        t[y][x] += a[y][z] * b[z][x] % c;
        t[y][x] %= c;
    }
    repeat (y,2) repeat (x,2) dest[y][x] = t[y][x];
}
int main() {
    int n; cin >> n;
    ll x, t, a, b, c; cin >> x >> t >> a >> b >> c;
    {
        ll e[2][2] = { { a, b }, { 0, 1 } };
        ll f[2][2] = { { 1, 0 }, { 0, 1 } };
        for (int i = 0; (1ll << i) <= t; ++i) {
            if (t & (1ll << i)) mul(f, f, e, c);
            mul(e, e, e, c);
        }
        a = f[0][0];
        b = f[0][1];
    }
    ll s = 0;
    repeat (i,n) {
        s += x;
        x = (a*x%c + b) % c;
    }
    cout << s << endl;
    return 0;
}
```
