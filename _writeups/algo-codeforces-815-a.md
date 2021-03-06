---
layout: post
redirect_from:
  - /writeup/algo/codeforces/815-a/
  - /blog/2017/06/18/cf-815-a/
date: "2017-06-18T03:07:23+09:00"
tags: [ "competitive", "writeup", "codeforces" ]
"target_url": [ "http://codeforces.com/contest/815/problem/A" ]
---

# Codeforces Round #419 (Div. 1): A. Karen and Game

ストーリー短くて読みやすいなあと思ってたら誤読してた。
hackしてくれた人に感謝。

## solution

ある列/行$x$を見てその最小値が正なら`row x`/`col x`を貪欲にするので(ほとんど)よい。
ただし回数は最小化する必要があることに注意して、この部分だけ適当にする。$O(NM)$。

## implementation

``` c++
#include <algorithm>
#include <climits>
#include <cstdio>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define whole(f, x, ...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using namespace std;
template <class T> inline void setmin(T & a, T const & b) { a = min(a, b); }
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

int main() {
    int h, w; scanf("%d%d", &h, &w);
    vector<vector<int> > g = vectors(h, w, int()); repeat (y, h) repeat (x, w) scanf("%d", &g[y][x]);
    int base = INT_MAX;
    repeat (y, h) {
        repeat (x, w) {
            setmin(base, g[y][x]);
        }
    }
    repeat (y, h) {
        repeat (x, w) {
            g[y][x] -= base;
        }
    }
    vector<int> row(h);
    repeat (y, h) {
        row[y] = *whole(min_element, g[y]);
        repeat (x, w) g[y][x] -= row[y];
    }
    vector<int> col(w);
    repeat (x, w) {
        col[x] = INT_MAX;
        repeat (y, h) setmin(col[x], g[y][x]);
        repeat (y, h) g[y][x] -= col[x];
    }
    bool is_cleared = true;
    repeat (y, h) {
        repeat (x, w) {
            if (g[y][x] != 0) {
                is_cleared = false;
            }
        }
    }
    if (is_cleared) {
        int n = 0;
        n += base * min(h, w);
        repeat (y, h) n += row[y];
        repeat (x, w) n += col[x];
        printf("%d\n", n);
        if (h < w) {
            repeat (y, h) repeat (i, base) printf("row %d\n", y+1);
        } else {
            repeat (x, w) repeat (i, base) printf("col %d\n", x+1);
        }
        repeat (y, h) repeat (i, row[y]) printf("row %d\n", y+1);
        repeat (x, w) repeat (i, col[x]) printf("col %d\n", x+1);
    } else {
        printf("-1\n");
    }
    return 0;
}
```
