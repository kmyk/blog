---
layout: post
alias: "/blog/2016/12/29/srm-704-easy/"
date: "2016-12-29T22:58:27+09:00"
tags: [ "competitive", "writeup", "topcoder", "srm", "graph", "tree", "construction" ]
---

# TopCoder SRM 704 Div1 Easy: TreeDistanceConstruction

AGC 005 Cがこれの存在判定だけするものだったらしい。

## problem

長さ$N$の数列$d$が与えられる。頂点数$N$の木で以下を満たすものを(存在するならば)ひとつ構成し出力せよ。

-   任意の頂点$i$について、その頂点から最も遠い頂点を$j$としたとき、距離$d(i,j) = d_i$

## solution

Fix the centeral vertex(s) and put others to it in the ascending order of $d_i$. $O(N)$.

Let $C = \operatorname{argmin}\_i d_i$, then $\|C\| \le 2$ holds or to construct is impossible.
Make the centeral vertex/edge from $C$, and put other vertices to the both side of it in the ascending order of $d_i$.
Validating the constructed tree with $O(N^3)$ helps you to avoid corner cases.

## implementation

``` c++
#include <bits/stdc++.h>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using namespace std;
template <class T> void setmax(T & a, T const & b) { if (a < b) a = b; }
template <class T> void setmin(T & a, T const & b) { if (b < a) a = b; }
const int inf = 1e9+7;
class TreeDistanceConstruction { public: vector<int> construct(vector<int> d); };

vector<int> TreeDistanceConstruction::construct(vector<int> d) {
    int n = d.size();
    vector<int> result;
    int min_d = *whole(min_element, d);
    int cnt_min_d = whole(count, d, min_d);
    if (cnt_min_d == 1 or cnt_min_d == 2) { // construct
        int l = whole(find, d, min_d) - d.begin();
        int r;
        if (cnt_min_d == 1) {
            r = l;
        } else {
            r = find(d.begin() + l + 1, d.end(), min_d) - d.begin();
            result.push_back(l);
            result.push_back(r);
        }
        int m = l;
        int tick = 0;
        vector<int> que(n);
        whole(iota, que, 0);
        whole(sort, que, [&](int i, int j) { return d[i] < d[j]; });
        repeat_from (top, cnt_min_d, n) {
            int i = que[top];
            if (d[m] + 1 < d[i]) {
                tick = 0;
                m = l;
            }
            if (tick == 0) {
                result.push_back(l);
                result.push_back(i);
                l = i;
            } else if (tick == 1) {
                result.push_back(r);
                result.push_back(i);
                r = i;
            } else {
                result.push_back(m);
                result.push_back(i);
            }
            ++ tick;
        }
    } else {
        // impossible
    }
    if (not result.empty()) { // validate
        vector<vector<int> > dist(n, vector<int>(n, inf));
        repeat (i,n) dist[i][i] = 0;
        repeat (i,n-1) {
            int u = result[2*i  ];
            int v = result[2*i+1];
            dist[u][v] = 1;
            dist[v][u] = 1;
        }
        repeat (k,n) { // warshall floyd
            repeat (i,n) {
                repeat (j,n) {
                    setmin(dist[i][j], dist[i][k] + dist[k][j]);
                }
            }
        }
        vector<int> eccentricity(n);
        repeat (i,n) {
            repeat (j,n) {
                setmax(eccentricity[i], dist[i][j]);
            }
        }
        repeat (i,n) {
            if (d[i] != eccentricity[i]) {
                result.clear();
            }
        }
    }
    return result;
}
```
