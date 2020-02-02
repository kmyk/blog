---
layout: post
alias: "/blog/2017/03/13/agc-011-e/"
date: "2017-03-13T01:49:43+09:00"
title: "AtCoder Grand Contest 011: E - Increasing Numbers"
tags: [ "competitive", "writeup", "atcoder", "agc", "multiprecision" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc011/tasks/agc011_e" ]
---

解説を見てそのまま書いた。
pythonでやると入力取って$9$の乗算1回に$1.5$秒ぐらいで基数変換が走っててだめそうだった。なのでc++した。
他の人の提出を見るとみな全て融合させてるのか陽に多倍長整数演算してる人は見つからなかった。

## solution

数式を整理して二分探索。$L = \log\_{10} N$に対し$O(L \log L)$。

任意の増加的な数は高々$9$個の[repunits](https://ja.wikipedia.org/wiki/%E3%83%AC%E3%83%94%E3%83%A5%E3%83%8B%E3%83%83%E3%83%88)の和で表わせる。
隣り合う桁ごとの差分の総和は(先頭には無限に`0`があるとして)高々$9$であり、$r$回の増加をひとつひとつに分解すると$r$個のrepunitsになるため。
imos法っぽい。
逆に、高々$9$個のrepunitsの和は増加的であるのも言える。
よって高々$9k$個のrepunitsで$N$を表現できる$k$で最小のものが答え。

任意のrepunitは$\frac{10^r - 1}{9}$と表わせる。
これは$\underbrace{111 \dots 1}\_r = \sum\_{i \lt r} 10^i = \frac{10^r - 1}{10 - 1}$とすれば式変形でも出る。
$r = 0$を含む。
$9k$個以下のrepunitsの和で$N$が表現できるとは、$N = \sum\_{i \lt 9k} \frac{10^{r_i} - 1}{9}$な$r_i$が存在すること。
$\sum\_{i \lt 9k} 10^{r_i} = 9N + 9k$と変形できるので、この存在性は$9N + 9k$の各桁の和が$9k$以下であるかどうかで分かる。

これで$k$を二分探索すればよい。
二分探索の上限$R$は桁数$L = \lfloor \log\_{10} N \rfloor + 1$ぐらいあればよい。
以下のようにする。
$\sum\_{i \lt 9k} 10^{r_i} = 9N + 9k$として$\sum\_{i \lt 9k} r_i \le 9k$を成り立たせることを考える。
$k \ll N$から$9N + 9k \approx 9N$のため不等式左辺は高々$9 \log\_{10} 9N$。
よって$\log\_{10} 9N \le k$ならよくて、これは$\log\_{10} 9 = 0.954\dots$なので$\log\_{10} 9N \approx L$。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <numeric>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using namespace std;
vector<int8_t> encode(string const & x) {
    int n = x.size();
    vector<int8_t> y(n);
    repeat (i,n) y[n-i-1] = x[i] - '0';
    return y;
}
vector<int8_t> encode(int x) {
    vector<int8_t> y;
    while (x) {
        y.push_back(x % 10);
        x /= 10;
    }
    return y;
}
void normalize(vector<int8_t> & x) {
    int n = x.size();
    repeat (i,n) {
        while (x[i] < 0) {
            assert (i+1 != n);
            x[i+1] -= 1;
            x[i] += 10;
        }
        while (10 <= x[i]) {
            assert (i+1 != n);
            x[i+1] += 1;
            x[i] -= 10;
        }
    }
    while (not x.empty() and x.back() == 0) x.pop_back();
}
vector<int8_t> add(vector<int8_t> const & x, vector<int8_t> const & y) {
    int n = max(x.size(), y.size());
    vector<int8_t> z(n);
    repeat (i, x.size()) z[i] += x[i];
    repeat (i, y.size()) z[i] += y[i];
    normalize(z);
    return z;
}
vector<int8_t> mul(vector<int8_t> const & x, int8_t k) {
    int n = x.size();
    vector<int8_t> y(n+1);
    repeat (i,n) {
        y[i+1] += x[i] * k / 10;
        y[i  ] += x[i] * k % 10;
    }
    normalize(y);
    return y;
}
bool pred(vector<int8_t> const & n, int k) {
    vector<int8_t> a = mul(add(n, encode(k)), 9);
    return whole(accumulate, a, 0) <= 9 * k;
}
int main() {
    string s; cin >> s;
    vector<int8_t> n = encode(s);
    int l = 0;
    int r = 9 * s.size();
    while (r - l > 1) {
        int m = (l + r) / 2;
        (pred(n, m) ? r : l) = m;
    }
    cout << r << endl;
    return 0;
}
```
