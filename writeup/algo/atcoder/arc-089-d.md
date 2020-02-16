---
layout: post
alias: "/blog/2018/01/23/arc-089-d/"
date: "2018-01-23T19:41:42+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "imos" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc089/tasks/arc089_b" ]
---

# AtCoder Regular Contest 089: D - Checker

ただの2次元imosなんだけど1次元imosを2回やってしまったので大変だった。実装が下手糞。

## solution

$0 \le x\_i, y\_i \le 10^9$であるがそれぞれ$2K$で割った余りで考えてよい。
格子の位置は$(2K)^2$通りしかないがこれは総当たりできる。
要求の数を数えるのは2次元imos法でやる。
$O(N + K^2)$。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
using namespace std;
template <class T> inline void chmax(T & a, T const & b) { a = max(a, b); }
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

int main() {
    // input
    int n, k; scanf("%d%d", &n, &k);
    vector<int> x(n), y(n); vector<char> c(n);
    REP (i, n) scanf("%d%d %c", &x[i], &y[i], &c[i]);
    // solve
    auto acc = vectors(2 * k, 2 * k + 1, array<int, 2>({}));
    REP (i, n) {
        acc[y[i] % (2 * k)][x[i] % (2 * k) + 1][c[i] == 'B'] += 1;
    }
    REP (y, 2 * k) {
        REP (x, 2 * k) {
            REP (p, 2) {
                acc[y][x + 1][p] += acc[y][x][p];
            }
        }
    }
    int result = 0;
    REP (x, 2 * k) {
        vector<array<int, 2> > accx(2 * k + 1);
        REP (y, 2 * k) {
            int b, w;
            if (x < k) {
                b =                     acc[y][x + k][1] - acc[y][x][1];
                w = acc[y][2 * k][0] - (acc[y][x + k][0] - acc[y][x][0]);
            } else {
                b = acc[y][2 * k][1] - (acc[y][x][1] - acc[y][x - k][1]);
                w =                     acc[y][x][0] - acc[y][x - k][0];
            }
            int total = acc[y][2 * k][0] + acc[y][2 * k][1];
            accx[y + 1][1] = accx[y][1] + (b + w);
            accx[y + 1][0] = accx[y][0] + (total - (b + w));
        }
        REP (y, 2 * k) {
            int b, w;
            if (y < k) {
                b =                   accx[y + k][1] - accx[y][1];
                w = accx[2 * k][0] - (accx[y + k][0] - accx[y][0]);
            } else {
                b = accx[2 * k][1] - (accx[y][1] - accx[y - k][1]);
                w =                   accx[y][0] - accx[y - k][0];
            }
            chmax(result, b + w);
        }
    }
    // output
    printf("%d\n", result);
    return 0;
}
```
