---
layout: post
redirect_from:
  - /writeup/algo/aoj/1337/
  - /blog/2017/12/04/aoj-1337/
date: "2017-12-04T10:53:20+09:00"
tags: [ "competitive", "writeup", "aoj", "icpc", "icpc-asia", "graph", "connected-components", "coordinate-compression" ]
"target_url": [ "http://judge.u-aizu.ac.jp/onlinejudge/description.jsp?id=1337" ]
---

# AOJ 1337. Count the Regions

私は実装担当なので、後輩が読んで解法まで出したので実装するだけだった。頭いい解法という感じがするし自分でやって思い付けたか少し不安になる。

## problem

軸平行な長方形をたくさん書く。空間はいくつに分割されるか。

## solution

各座標を$2$倍して実際に模様を作り、連結成分の数を数えるだけ。ただし座標圧縮する。$O(N^2)$。

## implementation

``` c++
#include <algorithm>
#include <cstdio>
#include <functional>
#include <map>
#include <numeric>
#include <stack>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i, m, n) for (int i = (m); (i) < int(n); ++(i))
#define whole(x) begin(x), end(x)
using namespace std;
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }
const int dy[] = { -1, 1, 0, 0 };
const int dx[] = { 0, 0, 1, -1 };

template <typename T>
map<T, int> coordinate_compression_map(vector<T> const & xs) {
    int n = xs.size();
    vector<int> ys(n);
    iota(whole(ys), 0);
    sort(whole(ys), [&](int i, int j) { return xs[i] < xs[j]; });
    map<T,int> f;
    for (int i : ys) {
        if (not f.count(xs[i])) { // make unique
            int j = f.size();
            f[xs[i]] = j; // f[xs[i]] has a side effect, increasing the f.size()
        }
    }
    return f;
}

int main() {
    while (true) {
        // input
        int n; scanf("%d", &n);
        if (n == 0) break;
        vector<int> l(n), t(n), r(n), b(n);
        repeat (i, n) {
            scanf("%d%d%d%d", &l[i], &t[i], &r[i], &b[i]);
        }
        // solve
        // // compress
        vector<int> xs, ys;
        repeat (i, n) {
            xs.push_back(l[i]);
            ys.push_back(t[i]);
            xs.push_back(r[i]);
            ys.push_back(b[i]);
        }
        sort(whole(ys)); ys.erase(unique(whole(ys)), ys.end());
        sort(whole(xs)); xs.erase(unique(whole(xs)), xs.end());
        map<int, int> cy = coordinate_compression_map(ys);
        map<int, int> cx = coordinate_compression_map(xs);
        // // dfs
        int h = cy.size();
        int w = cx.size();
        auto f = vectors(2 * h + 3, 2 * w + 3, false);
        repeat (y, 2 * h + 3) f[y][0] = f[y][2 * w + 2] = true;
        repeat (x, 2 * w + 3) f[0][x] = f[2 * h + 2][x] = true;
        repeat (i, n) {
            repeat_from (y, 2 * cy[b[i]] + 2, 2 * cy[t[i]] + 3) f[y][2 * cx[l[i]] + 2] = f[y][2 * cx[r[i]] + 2] = true;
            repeat_from (x, 2 * cx[l[i]] + 2, 2 * cx[r[i]] + 3) f[2 * cy[b[i]] + 2][x] = f[2 * cy[t[i]] + 2][x] = true;
        }
        int result = 0;
        stack<pair<int, int> > stk;
        repeat (y, 2 * h + 3) repeat (x, 2 * w + 3) if (not f[y][x]) {
            result += 1;
            f[y][x] = true;
            stk.emplace(y, x);
            while (not stk.empty()) {
                int y, x; tie(y, x) = stk.top(); stk.pop();
                repeat (i, 4) {
                    int ny = y + dy[i];
                    int nx = x + dx[i];
                    if (not f[ny][nx]) {
                        f[ny][nx] = true;
                        stk.emplace(ny, nx);
                    }
                }
            }
        }
        // output
        printf("%d\n", result);
    }
    return 0;
}
```
