---
layout: post
redirect_from:
  - /writeup/algo/atcoder/abc-033-d/
  - /blog/2016/02/07/abc-033-d/
date: 2016-02-07T01:53:04+09:00
tags: [ "competitive", "writeup", "atcoder", "abc", "angle", "geometry", "sort" ]
---

# AtCoder Beginner Contest 033 D - 三角形の分類

角度ソート系の発想は苦手。誤差に敏感な実装も苦手。
とりあえず一定の数を解いて慣れるしかないのだろうか。

## [D - 三角形の分類](https://beta.atcoder.jp/contests/abc033/tasks/abc033_d)

### 解説

$\frac{n(n-1)(n-2)}{6}$個の三角形の持つ鋭角/直角/鈍角の数を考える。
これらが分かれば鋭角三角形/直角三角形/鈍角三角形の数も分かる。

点をひとつ固定して考える。
その点を頂点とする角は$\frac{(n-1)(n-2)}{2}$個あるが、これをまとめて数えたい。
その点を中心として他の点を角度でソートすれば、角の数を区間の長さとしてまとめて数えることができ、計算量が$n$落ちる。

### 実装

`const long double EPS = 1e-6;`とするとwaする。

``` c++
#define _USE_MATH_DEFINES
#include <iostream>
#include <vector>
#include <algorithm>
#include <cmath>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;
const long double EPS = 1e-10;
int main() {
    ll n; cin >> n;
    vector<int> y(n), x(n);
    repeat (i,n) cin >> x[i] >> y[i];
    ll acute_angle = 0;
    ll right = 0;
    repeat (i,n) {
        vector<long double> angles;
        repeat (j,n) if (j != i) angles.push_back(atan2l(y[j] - y[i], x[j] - x[i]));
        sort(angles.begin(), angles.end());
        repeat (j,n-1) angles.push_back(angles[j] + 2*M_PI);
        int k = 0;
        repeat (j,n-1) {
            while (angles[k+1] - angles[j] < M_PI/2 - EPS) ++ k;
            acute_angle += k - j;
            assert (M_PI/2 - EPS <= angles[k+1] - angles[j]);
            if (angles[k+1] - angles[j] < M_PI/2 + EPS) ++ right;
        }
    }
    ll all_angle = n*(n-1)*(n-2)/6;
    ll obtuse = 3*all_angle - acute_angle - right;
    ll acute = all_angle - right - obtuse;
    cout << acute << ' ' << right << ' ' << obtuse << endl;
    return 0;
}
```
