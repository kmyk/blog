---
layout: post
redirect_from:
  - /blog/2017/10/03/jag2017summer-day3-c/
date: "2017-10-03T06:58:38+09:00"
tags: [ "competitive", "writeup", "atcoder", "jag-summer", "graph", "construction" ]
"target_url": [ "https://beta.atcoder.jp/contests/jag2017summer-day3/tasks/jag2017summer_day3_c" ]
---

# Japan Alumni Group Summer Camp 2017 Day 3: C - Ninja Map

これもバグらせた。それでも私が全部実装する方が速いと思うがやはり不安定。本番こけたらごめんなさいという気持ち。

## problem

$N \times N$の格子がある。
頂点番号はshuffleされている。
その$2N^2 - 2N$個の接続関係が全て与えられるので、そのようなものをひとつ構築せよ。

## solution

次数が$2$のものをひとつ選んで左上に置き、その隣をひとつ決めれば、後は次数や接続関係が整合するように一意に定まる。
$O(N^2)$。

## implementation

``` c++
#include <algorithm>
#include <cassert>
#include <cstdio>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define whole(x) begin(x), end(x)
using namespace std;
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }
const int dy[] = { -1, 1, 0, 0 };
const int dx[] = { 0, 0, 1, -1 };
bool is_on_field(int y, int x, int h, int w) { return 0 <= y and y < h and 0 <= x and x < w; }

int main() {
    // input
    int n; scanf("%d", &n);
    vector<vector<int> > g(n * n);
    repeat (i, 2 * n * (n - 1)) {
        int a, b; scanf("%d%d", &a, &b); -- a; -- b;
        g[a].push_back(b);
        g[b].push_back(a);
    }

    // solve
    auto f = vectors(n, n, -1);
    vector<bool> used(n * n);
    auto use = [&](int y, int x, int i) {
        assert (not used[i]);
        f[y][x] = i;
        used[i] = true;
    };
    repeat (i, n * n) {
        if (g[i].size() == 2) {
            use(0, 0, i);
            break;
        }
    }
    auto touch = [&](int py, int px, int y, int x, int degree) {
        int i = f[py][px];
        for (int j : g[i]) if (not used[j] and g[j].size() == degree) {
            bool valid = true;
            repeat (k, 4) {
                int ny = y + dy[k];
                int nx = x + dx[k];
                if (not is_on_field(ny, nx, n, n)) continue;
                if (f[ny][nx] == -1) continue;
                if (not count(whole(g[j]), f[ny][nx])) {
                    valid = false;
                    break;
                }
            }
            if (valid) {
                use(y, x, j);
                return;
            }
        }
        assert (false);
    };
    repeat (y, n) {
        repeat (x, n - 1) {
            int degree = 4 - (y == 0 or y == n - 1) - (x + 1 == n - 1);
            touch(y, x, y, x + 1, degree);
        }
        if (y + 1 < n) {
            int degree = 3 - (y + 1 == n - 1);
            touch(y, 0, y + 1, 0, degree);
        }
    }

    // output
    repeat (y, n) {
        repeat (x, n) {
            printf("%d%c", f[y][x] + 1, x < n - 1 ? ' ' : '\n');
        }
    }
    return 0;
}
```
