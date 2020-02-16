---
layout: post
redirect_from:
  - /blog/2018/01/04/codefestival-2016-grand-final-b/
date: "2018-01-04T16:09:19+09:00"
tags: [ "competitive", "writeup", "atcodr", "codefestival", "geometry" ]
"target_url": [ "https://beta.atcoder.jp/contests/cf16-exhibition-final/tasks/cf16_exhibition_final_b" ]
---

# CODE FESTIVAL 2016 Grand Final: B - Inscribed Bicycle

## solution

頑張って計算。$O(1)$。

頂点に$A, B, C$と名前を付ける。
頂点への名前の付け方を全部試すとして、円$1$は辺$AB$と$AC$に、円$2$は辺$BA$と$BC$に接するとしてよい。
さらに円$1$と円$2$も接する。
そのような状況のときの$r$は式を立てて計算すれば一意に求まる。

## implementation

``` c++
#include <algorithm>
#include <cmath>
#include <complex>
#include <cstdio>
using namespace std;
template <class T> inline void setmax(T & a, T const & b) { a = max(a, b); }

double solve1(int x1, int y1, int x2, int y2, int x3, int y3) {
    complex<double> a1(x1 - x3, y1 - y3);
    complex<double> a2(x2 - x3, y2 - y3);
    double arg1 = abs(arg(a1 / a2));
    double arg2 = M_PI - abs(arg((a1 - a2) / a2));
    double scale = abs(a2);
    return scale / (2 + 1 / tan(arg1 / 2) + 1 / tan(arg2 / 2));
}

int main() {
    // input
    int x1, y1; scanf("%d%d", &x1, &y1);
    int x2, y2; scanf("%d%d", &x2, &y2);
    int x3, y3; scanf("%d%d", &x3, &y3);
    // solve
    double result = 0;
    setmax(result, solve1(x1, y1, x2, y2, x3, y3));
    setmax(result, solve1(x2, y2, x3, y3, x1, y1));
    setmax(result, solve1(x3, y3, x1, y1, x2, y2));
    // output
    printf("%.12lf\n", result);
    return 0;
}
```
