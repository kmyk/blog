---
layout: post
alias: "/blog/2016/10/10/jag2016autumn-j/"
date: "2016-10-10T21:51:39+09:00"
title: "JAG Practice Contest for ACM-ICPC Asia Regional 2016: J - Compressed Formula"
tags: [ "competitive", "writeup", "atcoder", "jag", "icpc", "matrix", "exponentiation-by-squaring" ]
"target_url": [ "https://beta.atcoder.jp/contests/jag2016autumn/tasks/icpc2016autumn_j" ]
---

この問題はかなり好き。

セット全体ではABCDEFJを解いて$7$完。本番でもこれぐらいの成績を取りたい。

## problem

`0` `1` `2` `3` `4` `5` `6` `7` `8` `9` `*` `+` `-`のみからなる数式が与えられるので計算せよ。
ただし数式は$s_1^{r_1} s_2^{r_2} \dots s_n^{r_n}$という繰り返しを用いた形で与えられる巨大なものである。

## solution

数式中の各文字を命令とみて行列の繰り返し二乗法。$O(N \log r_i)$。

数式を左から舐めていくとこを考える。
式/項/数の3段階があって、`*`は数の区切りであり、`+` `-`は項の区切りである。
数字に関して、stack系の言語でよく見る[^1]感じの$10$倍して足すやつと見る。
つまり以下のような仮想機械を考える。

-   状態
    -   式 $a$
    -   項 $b$
    -   数 $c$
-   命令
    -   `+`: $a \gets a+bc ; b \gets +1 ; c \gets 0$
    -   `-`: $a \gets a+bc ; b \gets -1 ; c \gets 0$
    -   `*`: $b \gets bc ; c \gets 0$
    -   数字 `d`: $c \gets 10c + d$

これを繰り返すことを考えると、各操作を行列で表現したい。
$bc$という項が出現し非線形に見えるが、これをひとつの変数として見れば線形になる。

-   状態
    -   $$ \begin{pmatrix}a \\\\ b \\\\ bc \\\\ 1 \end{pmatrix} $$
-   命令
    -   `+`: $$ \begin{pmatrix}a + bc \\\\ +1 \\\\ 0 \\\\ 1 \end{pmatrix} = \begin{pmatrix}1 & 0 & 1 & 0 \\\\ 0 & 0 & 0 & +1 \\\\ 0 & 0 & 0 & 0 \\\\ 0 & 0 & 0 & 1 \end{pmatrix} \begin{pmatrix}a \\\\ b \\\\ bc \\\\ 1 \end{pmatrix} $$
    -   `-`: $$ \begin{pmatrix}a + bc \\\\ -1 \\\\ 0 \\\\ 1 \end{pmatrix} = \begin{pmatrix}1 & 0 & 1 & 0 \\\\ 0 & 0 & 0 & -1 \\\\ 0 & 0 & 0 & 0 \\\\ 0 & 0 & 0 & 1 \end{pmatrix} \begin{pmatrix}a \\\\ b \\\\ bc \\\\ 1 \end{pmatrix} $$
    -   `*`: $$ \begin{pmatrix}a \\\\ bc \\\\ 0 \\\\ 1 \end{pmatrix} = \begin{pmatrix}1 & 0 & 0 & 0 \\\\ 0 & 0 & 1 & 0 \\\\ 0 & 0 & 0 & 0 \\\\ 0 & 0 & 0 & 1 \end{pmatrix} \begin{pmatrix}a \\\\ b \\\\ bc \\\\ 1 \end{pmatrix} $$
    -   数字 `d`: $$ \begin{pmatrix}a \\\\ b \\\\ 10bc+\mathrm{d}b \\\\ 1 \end{pmatrix} = \begin{pmatrix}1 & 0 & 0 & 0 \\\\ 0 & 1 & 0 & 0 \\\\ 0 & \mathrm{d} & 10 & 0 \\\\ 0 & 0 & 0 & 1 \end{pmatrix} \begin{pmatrix}a \\\\ b \\\\ bc \\\\ 1 \end{pmatrix} $$

## implementation

``` c++
#include <iostream>
#include <vector>
#include <array>
#include <cctype>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;
const int mod = 1e9+7;
const int N = 4;
typedef array<ll,N> vec4;
typedef array<array<ll,N>,N> mat44;
mat44 operator * (mat44 const & a, mat44 const & b) {
    mat44 c = {};
    repeat (k,N) {
        repeat (i,N) {
            repeat (j,N) {
                c[i][j] += a[i][k] * b[k][j];
                c[i][j] += mod;
                c[i][j] %= mod;
            }
        }
    }
    return c;
}
vec4 operator * (mat44 const & a, vec4 const & b) {
    vec4 c = {};
    repeat (k,N) {
        repeat (i,N) {
            c[i] += a[i][k] * b[k];
            c[i] += mod;
            c[i] %= mod;
        }
    }
    return c;
}
mat44 to_matrix(ll (& a)[N][N]) {
    mat44 b = {};
    repeat (i,N) {
        repeat (j,N) {
            b[i][j] = a[i][j];
        }
    }
    return b;
}
mat44 unit() {
    mat44 f = {};
    repeat (i,N) f[i][i] = 1;
    return f;
}
mat44 powm(mat44 x, ll r) {
    mat44 y = unit();
    for (ll i = 1; i <= r; i <<= 1) {
        if (r & i) y = y * x;
        x = x * x;
    }
    return y;
}

mat44 digit(int d) {
    ll f[N][N] = {
        { 1, 0,  0, 0 },
        { 0, 1,  0, 0 },
        { 0, d, 10, 0 },
        { 0, 0,  0, 1 },
    };
    return to_matrix(f);
}
mat44 mult() {
    ll f[N][N] = {
        { 1, 0, 0, 0 },
        { 0, 0, 1, 0 },
        { 0, 0, 0, 0 },
        { 0, 0, 0, 1 },
    };
    return to_matrix(f);
}
mat44 add(bool is_positive) {
    ll f[N][N] = {
        { 1, 0, 1, 0 },
        { 0, 0, 0, is_positive ? 1 : -1 },
        { 0, 0, 0, 0 },
        { 0, 0, 0, 1 },
    };
    return to_matrix(f);
}
int main() {
    int n; cin >> n;
    vector<int> r(n);
    vector<string> s(n);
    repeat (i,n) cin >> r[i] >> s[i];
    n += 1;
    r.push_back(1);
    s.push_back("+");
    vec4 x = { 0, 1, 0, 1 };
    repeat (i,n) {
        mat44 f = unit();
        for (char c : s[i]) {
            if (isdigit(c)) {
                f = digit(c - '0') * f;
            } else if (c == '*') {
                f = mult() * f;
            } else if (c == '+' or c == '-') {
                f = add(c == '+') * f;
            }
        }
        f = powm(f, r[i]);
        x = f * x;
    }
    cout << x[0] << endl;
    return 0;
}
```

[^1]: 例: <https://esolangs.org/wiki/Emmental>
