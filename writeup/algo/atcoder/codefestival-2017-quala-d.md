---
layout: post
redirect_from:
  - /blog/2017/10/03/codefestival-2017-quala-d/
date: "2017-10-03T06:36:53+09:00"
tags: [ "competitive", "writeup", "atcoder", "codefestival", "experiment" ]
"target_url": [ "https://beta.atcoder.jp/contests/code-festival-2017-quala/tasks/code_festival_2017_quala_d" ]
---

# CODE FESTIVAL 2017 qual A: D - Four Coloring

問題文を読んでとりあえず雑に上から貪欲に決めていく実験を書き綺麗な模様を見たが、コードに落とすのを面倒がって貪欲を修正したもので通そうとした。
盤面の境界の影響でずれなどがあり、できそうに見えたが思っていたより難しくて時間を解かした。
結果は日本人内$63$位でパフォはぎりぎり橙。ボーダーは$60$位だったようで通過失敗。
まああと$2$回あるし通るでしょという気はするが、つらい。

## solution

実験。$d$が奇数なら市松模様でよい。
$d$が偶数なら$45$度回転したような市松模様。

## implementation

``` c++
#include <cstdio>
#include <string>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
using namespace std;
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

vector<vector<char> > solve(int h, int w, int d) {
    w = max(2 * h, w);
    auto f = vectors(h, w, char());
    if (d % 2 == 1) {
        repeat (y, h) repeat (x, w) {
            f[y][x] = (y + x) % 4 + 1;
        }
    } else {
        int k1 = d;
        int k2 = 0;
        int k3 = d;
        int k4 = 0;
        int dir = + 1;
        repeat (y, h) {
            string s = dir > 0 ?
                string(k1, '\x01') + string(k2, '\x02') + string(k3, '\x03') + string(k4, '\x04') :
                string(k2, '\x02') + string(k1, '\x01') + string(k4, '\x04') + string(k3, '\x03') ;
            repeat (x, w) {
                f[y][x] = s[((- y + x) % (2 * d) + 2 * d) % (2 * d)];
            }
            if (k1 - dir * 2 < 0 or k2 + dir * 2 < 0) dir *= -1;
            k1 -= dir * 2;
            k2 += dir * 2;
            k3 -= dir * 2;
            k4 += dir * 2;
        }
    }
    return f;
}

int main() {
    // input
    int h, w, d; scanf("%d%d%d", &h, &w, &d);

    // solve
    auto f = solve(h, w, d);

    // output
    repeat (y, h) {
        repeat (x, w) {
            printf("%c", ".RYGB"[f[y][x]]);
        }
        printf("\n");
    }
    return 0;
}
```
