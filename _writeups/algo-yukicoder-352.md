---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/352/
  - /blog/2016/03/11/yuki-352/
date: 2016-03-11T23:06:27+09:00
tags: [ "competitive", "writeup", "yukicoder", "expected-value", "probability" ]
---

# Yukicoder No.352 カード並べ

## [No.352 カード並べ](http://yukicoder.me/problems/750)

### 解法

「いずれかのカードとカードの間に入れて置く」が選ばれた場合、そのコストは置くカードの両隣のカードの数の積、であるが、両隣のカードは均等に出現する。

### 実装

``` c++
#include <iostream>
#include <cstdio>
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
typedef long long ll;
using namespace std;
int main() {
    int n; cin >> n;
    double ans = 0;
    ans += 1; // 1
    ans += 1; // 2
    repeat_from (i,3,n+1) {
        ll p = 0;
        int q = 0;
        repeat_from (a,1,i) repeat_from (b,a+1,i) {
            p += a * b;
            q += 1;
        }
        ans += (2 + (p /(double) q) * (i-2)) / i;
    }
    printf("%.10lf\n", ans);
    return 0;
}
```
