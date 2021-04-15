---
layout: post
redirect_from:
  - /writeup/algo/codeforces/601-c/
  - /blog/2015/11/25/cf-601-c/
date: 2015-11-25T23:46:25+09:00
tags: [ "competitive", "writeup", "codeforces", "dp", "probability", "expected-value" ]
---

# Codeforces Round #333 (Div. 1) C. Kleofáš and the n-thlon

本番は1時間を費やしたがさっぱり分からず。終わってからゆっくり考えたら分かった。本番感じていたほどには難しくはなかった。

<!-- more -->

## [C. Kleofáš and the n-thlon](http://codeforces.com/contest/601/problem/C) {#c}

### 問題

$m$人($m \le 1000$)の選手が$n$回($n \le 100$)試合を行う。
各試合に関して各々の選手の順位が定まる。同じ順位を持つ選手が複数存在することはない。
それぞれの選手に関して、全試合の順位の総和を総合得点と呼ぶ。
総合得点が少なさの順位を、総合順位と呼ぶ。総合順位に関しては、同じ順位を持つ選手が複数存在することがある。
ある選手の全試合での順位が与えられる。他の選手は皆一様な能力を持つとしたとき、その選手の総合順位の期待値を求めよ。

### 解法

基本となる解法は、ある他の選手が与えられた選手より小さい総合得点を得る確率$p$を求め、他の選手の数の$m-1$を掛け、順位はone-basedであるため$1$を足す、というものである。
ある総合得点を取る確率はdpで計算できる。

順位はzero-basedに直しておく。
$i$試合目まで行ったときの総合得点が$j$である確率$p\_{i,j}$は、$i$試合目で$k$位を取る確率を$q\_{i,k}$とすると、$p\_{i,j} = \Sigma\_{0 \le k \le j} p\_{i-1,k}q\_{i,j-k}$である。
総合得点$j$は、与えられた選手の総合得点まで見る必要があるため、$j \lt nm$の範囲を動く。
全体で$O(n^2m^2)$となる。

これの計算量を落とす必要がある。
$i$試合目で$k$位を取る確率$q\_{i,k}$は、与えられた選手の$i$試合目の順位が$x_i$のとき、

$$ \begin{array}{ll}
q_{i,k} = \frac{1}{m - 1} & (k \neq x_i, k \lt m) \\
q_{i,k} = 0 & (otherwise)
\end{array} $$

と、ほとんど一様であるので、これを利用する。
つまり、$p\_{i,j}$を求めるのに、$\Sigma\_{0 \le k \le j} p\_{i-1,k} \cdot \frac{1}{m -1}$から、$x_i$の部分だけ引けばよい。
これは累積和を取りながら舐めることで計算でき、計算量から$m$がひとつ落ち$O(n^2m)$となり通る。

表を書いて考えると分かりやすい。

### 実装

``` c++
#include <iostream>
#include <cstdio>
#include <vector>
#include <algorithm>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
int main() {
    int n, m; cin >> n >> m;
    vector<int> x(n); repeat (i,n) { cin >> x[i]; -- x[i]; }
    int score = accumulate(x.begin(), x.end(), 0);
    if (score == 0) { // because cur[0] does not exist
        cout << 1 << endl;
        return 0;
    }
    vector<double> cur(score);
    vector<double> prv(score);
    cur[0] = 1;
    repeat (i,n) {
        cur.swap(prv);
        cur.clear();
        cur.resize(score);
        double acc = 0;
        repeat (j, min(score, (i+1)*m)) {
            acc += prv[j];
            if (m <= j) acc -= prv[j-m];
            cur[j] = (acc - (x[i] <= j ? prv[j-x[i]] : 0)) / (m-1);
        }
    }
    printf("%.16lf\n", accumulate(cur.begin(), cur.end(), 0.0) * (m-1) + 1);
    return 0;
}
```
