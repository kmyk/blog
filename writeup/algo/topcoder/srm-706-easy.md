---
layout: post
alias: "/blog/2017/01/22/srm-706-easy/"
date: "2017-01-22T02:40:47+09:00"
title: "TopCoder SRM 704 Div1 Easy: MovingCandies"
tags: [ "competitive", "writeup", "topcoder", "srm", "dp" ]
---

## solution

DP. For a coordinate $(y, x)$ and a distance $d$, compute the minmum number of moved candies $\mathrm{dp}(y,x,d)$. $O((HW)^2)$.
You should take care that $d \le K$ must hold for the total number of candies $K$.

## implementation

``` c++
#include <bits/stdc++.h>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
using namespace std;
template <class T> void setmin(T & a, T const & b) { if (b < a) a = b; }
const int dy[] = { -1, 1, 0, 0 };
const int dx[] = { 0, 0, 1, -1 };
bool is_on_field(int y, int x, int h, int w) { return 0 <= y and y < h and 0 <= x and x < w; }
class MovingCandies { public: int minMoved(vector<string> t); };

const int inf = 1e9+7;
int MovingCandies::minMoved(vector<string> t) {
    int h = t.size();
    int w = t.front().size();
    int cnt = 0;
    repeat (y,h) repeat (x,w) if (t[y][x] == '#') cnt += 1;
    if (cnt < h + w - 1) return -1;
    int ans = inf;
    vector<vector<int> > cur(h, vector<int>(w, inf));
    vector<vector<int> > prv(h, vector<int>(w, inf));
    setmin(cur[0][0], int(t[0][0] == '.'));
    repeat_from (dist, 2, cnt+1) {
        cur.swap(prv);
        repeat (y,h) repeat (x,w) {
            cur[y][x] = inf;
            repeat (i,4) {
                int py = y + dy[i];
                int px = x + dx[i];
                if (not is_on_field(py, px, h, w)) continue;
                setmin(cur[y][x], prv[py][px] + int(t[y][x] == '.'));
            }
        }
        setmin(ans, cur[h-1][w-1]);
    }
    return ans;
}
```
