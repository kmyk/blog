---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/343/
  - /blog/2016/02/27/yuki-343/
date: 2016-02-27T13:48:50+09:00
tags: [ "competitive", "writeup", "yukicoder" ]
---

# Yukicoder No.343 手抜き工事のプロ

特に何もない普通の問題。でも[editorial](http://yukicoder.me/problems/707/editorial)で触れられてた話は面白かったです。

## [No.343 手抜き工事のプロ](http://yukicoder.me/problems/707)

### 解法

$O(N)$。

それより上の重さの総和を持ちながら、溶接が必要か判定しながら降りていく。

### 実装

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
const double eps = 1e-12;
int main() {
    int n; double l; cin >> n >> l;
    vector<double> x(n); x[0] = 0; repeat (i,n-1) cin >> x[i+1];
    reverse(x.begin(), x.end());
    int ans = 0;
    double acc = 0;
    repeat (i,n-1) {
        if (l - eps < abs(x[i+1] - x[i])) {
            ans = -1;
            break;
        }
        acc += x[i];
        if (l/2 - eps < abs(x[i] - acc/(i+1)) or l/2 - eps < abs(x[i+1] - acc/(i+1))) {
            ans += 1;
        }
    }
    cout << ans << endl;
    return 0;
}
```
