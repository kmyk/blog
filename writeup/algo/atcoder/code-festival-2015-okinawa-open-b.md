---
layout: post
alias: "/blog/2016/07/13/code-festival-2015-okinawa-open-b/"
date: "2016-07-13T02:52:41+09:00"
title: "CODE FESTIVAL 2015 OKINAWA OPEN B - Beware of the Sogginess!"
tags: [ "competitive", "writeup", "codefestival", "atcoder", "dp" ]
"target_url": [ "https://beta.atcoder.jp/contests/code-festival-2015-okinawa-open/tasks/code_festival_2015_okinawa_b" ]
---

解けず。必ず解くべき問題だった。DPは$\mathrm{dp} : X+1 \times Y+1 \to N+1$なやつだけ考えて棄却してたが、諦めて解説を見ようとしてDPの文字が目に入った瞬間に理解した。

<!-- more -->

## problem

$$\mathrm{ans} = \min \\{ \|S\| \mid S \subseteq N, t : N \to [0,1], \Sigma\_{i \in S} (a_i + \min \\{ t(i), b_i \\}) \ge X \land \Sigma\_{i \in S} \min \\{ b_i - t(i), 0 \\} \ge Y \\}$$.

## solution

DP. $O(N \cdot (X+Y))$.

The parameter $t$ is removable. i.e. it becomes $\mathrm{ans} = \min \\{ \|S\| \mid S \subseteq N, \Sigma\_{i \in S} (a_i + b_i) \ge X + Y \land \Sigma\_{i \in S} b_i \ge Y \\}$.
This is easily computable with $\mathrm{dp} : N+1 \land X+Y+1 \to Y$, which is a function to return the maximum $\Sigma\_{i \in S} b_i$ for $\|S\|$ and $\Sigma\_{i \in S} (a_i + b_i)$.

## implementation

``` c++
#include <cstdio>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_reverse(i,n) for (int i = (n)-1; (i) >= 0; --(i))
using namespace std;
template <class T> void setmax(T & a, T const & b) { if (a < b) a = b; }
template <class T> void setmin(T & a, T const & b) { if (b < a) a = b; }
const int inf = 1e9+7;
int main() {
    int n, x, y; scanf("%d%d%d", &n, &x, &y);
    vector<int> a(n), b(n); repeat (i,n) scanf("%d%d", &a[i], &b[i]);
    vector<vector<int> > dp(n+1, vector<int>(x+y+1, -1));
    dp[0][0] = 0;
    int ans = inf;
    repeat (i,n) {
        repeat_reverse (j,n) {
            repeat_reverse (k,x+y+1) {
                if (dp[j][k] != -1) {
                    int nk = min(x+y, k+a[i]+b[i]);
                    setmax(dp[j+1][nk], dp[j][k]+b[i]);
                    if (y <= dp[j+1][nk] and x+y <= nk) {
                        setmin(ans, j+1);
                    }
                }
            }
        }
    }
    if (ans == inf) ans = -1;
    printf("%d\n", ans);
    return 0;
}
```
