---
layout: post
redirect_from:
  - /blog/2017/05/28/agc-015-c/
date: "2017-05-28T03:30:10+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc", "tree", "graph" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc015/tasks/agc015_c" ]
---

# AtCoder Grand Contest 015: C - Nuske vs Phantom Thnook

Dの方が簡単に見える。
森$G = (V, E)$の成分の数は$\|V\| - \|E\|$ということだが、どこかの問題で有名なのだろうか。

## solution

青いマスは森をなし、木$G = (V, E)$は$\|V\| = \|E\| + 1$を満たす。なので領域中の青いマスの数$\|V\|$と青いマスを繋ぐ辺の数$\|E\|$を求めれば、木の本数は$\|V\| - \|E\|$として求まる。
これは累積和でひとつの領域に対し$O(1)$。よって$O(NM + Q)$。

## implementation

``` c++
#include <cstdio>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
using namespace std;
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

template <class T, class F>
vector<T> cumulative_sum(size_t n, F f) {
    vector<T> acc(n+1);
    repeat (i,n) {
        acc[i+1] = acc[i] + f(i);
    }
    return acc;
}
template <class T, class F>
vector<vector<T> > cumulative_sum(size_t h, size_t w, F f) {
    vector<vector<T> > acc(h+1, vector<T>(w+1));
    repeat (y,h) {
        repeat (x,w) {
            acc[y+1][x+1] = acc[y+1][x] + f(y, x);
            acc[y+1][x] += acc[y][x];
        }
        acc[y+1][w] += acc[y][w];
    }
    return acc;
}

int main() {
    int h, w, query; scanf("%d%d%d", &h, &w, &query);
    vector<vector<bool> > f = vectors(h, w, bool());
    repeat (y,h) {
        repeat (x,w) {
            char c; scanf(" %c", &c);
            f[y][x] = c != '0';
        }
    }
    auto g_hr = [&](int y, int x) { return x >= 1 and f[y][x-1] and f[y][x]; };
    auto g_vr = [&](int y, int x) { return y >= 1 and f[y-1][x] and f[y][x]; };
    auto g = [&](int y, int x) { return g_hr(y, x) + g_vr(y, x); };
    vector<vector<int> > acc = cumulative_sum<int>(h, w, [&](int y, int x) { return f[y][x] - g(y, x); });
    vector<vector<int> > hr(h); repeat (y,h) hr[y] = cumulative_sum<int>(w, [&](int x) { return g_vr(y, x); });
    vector<vector<int> > vr(w); repeat (x,w) vr[x] = cumulative_sum<int>(h, [&](int y) { return g_hr(y, x); });
    while (query --) {
        int ly, lx, ry, rx; scanf("%d%d%d%d", &ly, &lx, &ry, &rx); -- ly; -- lx; // [ly, ry) * [lx, rx)
        int result = 0;
        result += acc[ry][rx] - acc[ry][lx] - acc[ly][rx] + acc[ly][lx];
        result += hr[ly][rx] - hr[ly][lx];
        result += vr[lx][ry] - vr[lx][ly];
        printf("%d\n", result);
    }
    return 0;
}
```
