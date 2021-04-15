---
layout: post
redirect_from:
  - /writeup/algo/codeforces/332-b/
  - /blog/2016/01/07/cf-332-b/
date: 2016-01-07T22:53:21+09:00
tags: [ "competitive", "writeup", "codeforces", "dp", "cumulative-sum" ]
---

# Codeforces Round #193 (Div. 2) B. Maximum Absurdity

## [B. Maximum Absurdity](http://codeforces.com/contest/332/problem/B) {#b}

### 問題

長さ$n$の数列と整数$k$($0 \lt 2k \le n$)が与えられる。
数列から、長さ$k$の区間を交差しないように2個選ぶことを考える。
その2つの区間に含まれる数の総和を最大化するような選び方を答えよ。
複数存在する場合は区間の開始位置が辞書順で最も小さいものを答えよ。

### 解法

それまでの区間で総和が最大のものを持ちながら舐める。$O(n)$。

#### 詳細

まず、長さ$k$の区間の全てに関してその総和を計算しておく。累積和を使えば$O(n)$。
これにより、この数列中から要素を2つ取りその和を最大化する問題となる。ただし要素と要素の距離は$k$未満であってはならない。

数列を左から右へ順に見ていく。
このとき、今見ている項より左に$k$項以上離れた項の最大値を持っておく。
すると、見ている項を2個ある区間の内の右側の区間としたときの総和が得られる。
これの最大値を作る区間を答えればよい。

${\rm dp}\_{i,j} = \min\_{l+k-1\lt j}{\rm dp}\_{i-1,l}$といったdpとして説明することもできる。区間を2個ではなく$m$個選ぶように拡張したものを考えるとよいかもしれない。

### 実装

``` c++
#include <iostream>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
typedef long long ll;
using namespace std;
int main() {
    int n, k; cin >> n >> k;
    vector<ll> x(n); repeat (i,n) cin >> x[i];
    vector<ll> acc(n+1); repeat (i,n) acc[i+1] = acc[i] + x[i];
    vector<ll> y(n-k+1); repeat (i,n-k+1) y[i] = acc[i+k] - acc[i];
    int a = 0;
    int b = k;
    int best = y[0] >= y[1] ? 0 : 1;
    repeat_from (i,k+1,n-k+1) {
        if (y[a] + y[b] < y[best] + y[i]) {
            a = best;
            b = i;
        }
        if (y[best] < y[i-k+1]) {
            best = i-k+1;
        }
    }
    cout << a+1 << ' ' << b+1 << endl;
    return 0;
}
```
