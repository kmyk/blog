---
layout: post
redirect_from:
  - /writeup/algo/atcoder/agc-007-c/
  - /blog/2018/01/01/agc-007-c/
date: "2018-01-01T16:09:17+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc", "expected-value", "probability" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc007/tasks/agc007_c" ]
---

# AtCoder Grand Contest 007: C - Pushing Balls

分からなかった。Cの中では難しめに見える。
[editorial](http://agc007.contest.atcoder.jp/data/agc/007/editorial.pdf)は正直何を言っているのか分からないが、[解説放送](https://www.youtube.com/watch?v=6ZP8JyGsQBs)は分かりやすかったのでこちらを見よう。

## solution

次の$2$点。$O(N)$。

1.  与えられる間隔$d\_i$は階差数列になっているが、この間隔は全て$1$としてよい
2.  $f(n)$を$n$点あり$d\_1 = 1$で$x = 0$ (つまり間隔が全て$1$)のときの答えとすると、$f(n - 1)$から$f(n)$が$O(1)$で出る

(1)は言われればすぐ。
左から$i$番目の区間と右から$i$番目の区間をボールが通る回数の期待値は等しいので、それらの間で長さを融通しあってよい。
$i = 1$なら$d = \frac{d\_1 + d\_{2N}}{2} = \frac{2d\_1 + (2N - 1)x}{2} = d\_1 + (N - \frac{1}{2})x$であり$i \ne 1$でも全て等しい。
$d f(N)$が答え。

(2)はちょっとつらいが説明されれば分かる。$f(n)$を考える。
長さ$2n$の数列$d$の要素は全て$1$であるが、ボールを転がした後のボールと穴の間隔を考えると長さ$2n-2$の(全て$1$とは限らない)数列$d'$になる。
$d = (1, 1, 1, 1, 1, 1, \dots, 1, 1)$であり、最左のボールを左に転がすか最右のボールを右に転がせば同様に$d' = (1, 1, 1, 1, \dots, 1, 1)$。
それ以外だと転がし方に従って$d' = (3, 1, 1, 1, \dots, 1, 1), (1, 3, 1, 1, \dots, 1, 1), (1, 1, 3, 1, \dots, 1, 1), \dots, (1, 1, 1, 1, \dots, 1, 3)$。
期待値であるためこれらは平均してよくて全て$\frac{2n + 2}{2n}$の数列と見做せる。
よって$n \ge 2$のとき$f(n) = \frac{2n + 2}{2n}f(n - 1)$。

## implementation

``` c++
#include <cstdio>

double f(int n) {
    if (n == 0) return 0;
    if (n == 1) return 1;
    double d = (2 * n + 2.0) / (2 * n);
    return 1 + d * f(n - 1);
}

int main() {
    // input
    int n, d1, x; scanf("%d%d%d", &n, &d1, &x);
    // solve
    double d = d1 + (2 * n - 1) / 2.0 * x;
    double result = d * f(n);
    // output
    printf("%.15lf\n", result);
    return 0;
}
```
