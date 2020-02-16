---
layout: post
alias: "/blog/2016/06/19/tco-2016-round-2c-easy/"
date: 2016-06-19T20:33:05+09:00
tags: [ "competitive", "writeup", "tco", "topcoder", "geometry" ]
---

# TopCoderOpen 2016 Round 2C Easy: BearBall

I thought that my problem was going to be TLE, but it is accepted (even some people tried to hack).

## problem

平面上の点$p_1, p_2, \dots, p_N$ ($N \le 1500$)が与えられる。
$f(i,j)$を、$p_i$から$p_j$へ、点と点を線分で結んで繋ぐ際に使う必要のある線分の数の最小値とする。
ただし、線分がその端点以外で別の点を含むことは禁止する。
$\Sigma_i \Sigma_j f(i,j)$を答えよ。

## solution

At most $O(N^3)$.
Check whether all points are on the same line. If so, then the answer is simply $\Sigma_i \Sigma_j \|i - j\|$.
Else, a number of a round $f(i,j)$ is always $1$ or $2$. It becomes $1$ in trival cases, otherwise becomes $2$.
In non-trival case, you should select a point that minimizes the distance with the line $p_i - p_j$.

## implementation

``` c++
#include <bits/stdc++.h>
#include <tuple>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
using namespace std;
class BearBall { public: int countThrows(vector<int> x, vector<int> y); };

int BearBall::countThrows(vector<int> x, vector<int> y) {
    int n = x.size();
    {
        vector<pair<int,int> > z(n);
        repeat (i,n) z[i] = { x[i], y[i] };
        sort(z.begin(), z.end());
        repeat (i,n) tie(x[i], y[i]) = z[i];
    }
    bool is_on_line = true;;
    repeat_from (i,2,n) {
        int ax = x[1] - x[0];
        int ay = y[1] - y[0];
        int bx = x[i] - x[0];
        int by = y[i] - y[0];
        if (ay * bx - ax * by != 0) {
            is_on_line = false;
            break;
        }
    }
    if (is_on_line) {
        int ans = 0;
        repeat (i,n) ans += i*(i+1);
        return ans;
    } else {
        int ans = 0;
        repeat (j,n) {
            repeat (i,j) {
                int ax = x[j] - x[i];
                int ay = y[j] - y[i];
                bool is_direct = true;
                repeat_from (k,i+1,j) {
                    int bx = x[k] - x[i];
                    int by = y[k] - y[i];
                    if (ay * bx - ax * by == 0 and min(y[i],y[j]) <= y[k] and y[k] <= max(y[i],y[j])) {
                        is_direct = false;
                        break;
                    }
                }
                ans += 2 * (1 + not is_direct);
            }
        }
        return ans;
    }
}
```
