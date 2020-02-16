---
layout: post
redirect_from:
  - /writeup/algo/atcoder/agc-014-a/
  - /blog/2017/05/07/agc-014-a/
date: "2017-05-07T21:10:41+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc014/tasks/agc014_a" ]
---

# AtCoder Grand Contest 014: A - Cookie Exchanges

なんだかいけそうだったので試したら当たった。計算量解析は後からだけど、すこし面白かった。

## solution

愚直にやる。停止するか過去の状態に一致する(つまりloopが検出される)まで。
最終的にどれもが$\frac{A + B + C}{3}$へ近付いていき、特に差は毎回半分ぐらいになると見てよいので、$O(\log (A+B+C))$である。

## implementation

``` c++
#include <cstdio>
#include <algorithm>
#include <array>
#include <set>
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using ll = long long;
using namespace std;
int main() {
    array<int, 3> a;
    scanf("%d", &a[0]);
    scanf("%d", &a[1]);
    scanf("%d", &a[2]);
    whole(sort, a);
    set<array<int, 3> > used;
    while (     a[0] % 2 == 0
            and a[1] % 2 == 0
            and a[2] % 2 == 0) {
        used.insert(a);
        ll sum = a[0] +(ll) a[1] + a[2];
        a[0] = (sum - a[0]) / 2;
        a[1] = (sum - a[1]) / 2;
        a[2] = (sum - a[2]) / 2;
        whole(sort, a);
        if (used.count(a)) break;
    }
    if (used.count(a)) {
        printf("-1\n");
    } else {
        printf("%d\n", int(used.size()));
    }
    return 0;
}
```
