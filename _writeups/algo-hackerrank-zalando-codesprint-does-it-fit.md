---
layout: post
redirect_from:
  - /writeup/algo/hackerrank/zalando-codesprint-does-it-fit/
  - /blog/2016/06/05/hackerrank-zalando-codesprint-does-it-fit/
date: 2016-06-05T19:17:43+09:00
tags: [ "competitive", "writeup", "hackerrank" ]
"target_url": [ "https://www.hackerrank.com/contests/zalando-codesprint/challenges/does-it-fit" ]
---

# HackerRank Zalando CodeSprint: Does It Fit?

`C`のそれを$2r \le W \land 2r \le H$でなく$r \le W \land r \le H$としていたためにWAが生じ、$45$ptsしか取れなかった。
`R`の側のバグだと思っていたため気付けなかった。

## problem

$W \times H$の長方形がある。
以下の図形について、それを$W \times H$の長方形の中に収めることができるか答えよ。
回転させる操作は許されている。

-   半径$r$の円
-   $w \times h$の長方形

## solution

For circles, check $2r \le W \land 2r \le H$.

For rectangles, check $\exists \theta. x\cos\theta + y\sin\theta \le W \land x\sin\theta + y\cos\theta \le H$.
You can calculate this easily by checking for all $\theta \in \\{ 0, \Delta t, 2\Delta t, \dots, \frac{\pi}{2} - \Delta t, \frac{\pi}{2} \\}$.

## implementation

``` c++
#include <iostream>
#include <cmath>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
const double eps = 1e-10;
int main() {
    int w, h; cin >> w >> h;
    int n; cin >> n;
    while (n --) {
        char c; cin >> c;
        bool ans = false;;
        if (c == 'C') {
            int r; cin >> r;
            if (2*r <= w and 2*r <= h) ans = true;
        } else if (c == 'R') {
            int x, y; cin >> x >> y;
            if (x <= w and y <= h) ans = true;
            if (y <= w and x <= h) ans = true;
            if (not ans) {
                for (double t = 0; t <= M_PI/2; t += 0.0001) {
                    double wt = x * cos(t) + y * sin(t);
                    double ht = x * sin(t) + y * cos(t);
                    if (wt < w + eps and ht < h + eps) {
                        ans = true;
                        break;
                    }
                }
            }
        }
        cout << (ans ? "YES" : "NO") << endl;
    }
    return 0;
}
```
