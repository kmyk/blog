---
layout: post
alias: "/blog/2016/12/03/ddcc-2016-final-c/"
date: "2016-12-03T14:31:50+09:00"
title: "DISCO presents ディスカバリーチャンネル コードコンテスト2016 本戦: C - 01文字列"
tags: [ "competitive", "writeup", "atcoder", "ddcc" ]
"target_url": [ "https://beta.atcoder.jp/contests/ddcc2016-final/tasks/ddcc_2016_final_c" ]
---

## solution

先頭追加と末尾追加の操作の分け目がある。これを全部見る。$O(N)$。

文字列$T$を構成したとすると、その構成について分割$T = T_l T_r$があって、$T_l$の文字は先頭追加の操作によって$T_r$の文字は末尾追加の操作によって発生したものとなる。
逆にそのような分け目の位置$0 \le i \le n$を決めるとコストは$Ai + B(n-i) + Ck$となり、残る$k$は文字列中の`0` `1`の変わり目の数から定まる。
変わり目の数の累積和を取っておいてoff-by-oneを丁寧にすれば求まる。


部分点は$T$から始めて以下を繰り返して$\epsilon$にすればよい。反転操作をそのままやるとwell-foundedにならないので面倒。

-   コスト$A$で先頭の`0`を削る
-   コスト$B$で末尾の`1`を削る
-   コスト$C+A$で先頭の`1`を削って残りを反転
-   コスト$C+B$で末尾の`0`を削って残りを反転

## implementation

``` c++
#include <iostream>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;
template <class T> void setmin(T & a, T const & b) { if (b < a) a = b; }
const ll inf = ll(1e18)+9;
int main() {
    ll a, b, c; cin >> a >> b >> c;
    string t; cin >> t;
    int n = t.length();
    vector<int> flip(n+1);
    flip[0] = 0;
    repeat (i,n-1) flip[i+1] = flip[i] + (t[i] != t[i+1]);
    flip[n] = flip[n-1];
    ll ans = inf;
    repeat (i,n+1) {
        int lflip = max(0, flip[max(0, i-1)] + (i != 0 and t[  0] != '0'));
        int rflip = max(0, flip[n] - flip[i] + (i != n and t[n-1] != '1'));
        ll acc = 0;
        acc += a * i;
        acc += b * (n-i);
        acc += c * max(lflip, rflip);
        setmin(ans, acc);
    }
    cout << ans << endl;
    return 0;
}
```
