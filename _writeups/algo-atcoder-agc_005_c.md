---
layout: post
redirect_from:
  - /writeup/algo/atcoder/agc_005_c/
  - /writeup/algo/atcoder/agc-005-c/
  - /blog/2016/12/29/agc-005-c/
date: "2016-12-29T22:58:35+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc", "tree", "graph" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc005/tasks/agc005_c" ]
---

# AtCoder Grand Contest 005: C - Tree Restoring

SRM後に既出問として話題に上がったので。入出力部分だけ書き換えたら通った。

## solution

TopCoder SRM 704 Div1 Easy: TreeDistanceConstruction の部分問題なのでそれを見て。

## implementation

```
#include <bits/stdc++.h>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using namespace std;
template <class T> void setmax(T & a, T const & b) { if (a < b) a = b; }
template <class T> void setmin(T & a, T const & b) { if (b < a) a = b; }
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }
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
        vector<vector<int> > dist = vectors(n, n, inf);
        repeat (i,n) dist[i][i] = 0;
        repeat (i,n-1) {
            int u = result[2*i  ];
            int v = result[2*i+1];
            dist[u][v] = 1;
            dist[v][u] = 1;
        }
        repeat (k,n) { // W/F
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

int main() {
    int n; cin >> n;
    vector<int> a(n); repeat (i,n) cin >> a[i];
    cout << (TreeDistanceConstruction().construct(a).empty() ? "Impossible" : "Possible")  << endl;
    return 0;
}
```
