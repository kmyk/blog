---
layout: post
alias: "/blog/2017/07/14/icpc-2017-domestic-g/"
date: "2017-07-14T23:50:43+09:00"
title: "ACM-ICPC 2017 国内予選: G. 迷宮を一周"
tags: [ "competitive", "writeup", "icpc", "icpc-domestic", "cycle" ]
---

チームメンバーの助けを多いに借りて、いい感じに実装したらあまりよく分からないまま通った。

## solution

左手法、つまり壁に沿って一周するのでよい。$O(HW)$だと思う。

注意するのは次のような場合。不用意に細道に入ってはいけない。

```
...#.#...
...#.#...
...#.#...
...#.#...
...#.#...
.........
.........
.........
```

いい感じに実装する。

## implementation

``` c++
#include <cassert>
#include <functional>
#include <iostream>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < (n); ++ (i))
using namespace std;

const int dx[] = {0, 1, 0, -1}; // up right down left
const int dy[] = {-1, 0, 1, 0};

bool solve(int h, int w, const vector<string> & f) {
    auto is_on_field = [&](int y, int x) {
        return 0 <= x and x < w and 0 <= y and y < h;
    };
    vector<vector<bool> > visited(h, vector<bool>(w));
    function<bool (int, int, int, int)> go = [&](int y, int x, int tresuare, int left_hand) {
        assert (is_on_field(y, x) and f[y][x] == '.');
        if (y == 0     and x == w - 1 and tresuare == 0) tresuare += 1;
        if (y == h - 1 and x == w - 1 and tresuare == 1) tresuare += 1;
        if (y == h - 1 and x ==     0 and tresuare == 2) tresuare += 1;
        if (y == 0     and x ==     0 and tresuare == 3) return true;
        if (visited[y][x]) return false;
        visited[y][x] = true;
        for (int rotate = -1; rotate <= 1; ++ rotate) {
            int dir = (left_hand + rotate + 1) % 4;
            int ny = y + dy[dir];
            int nx = x + dx[dir];
            if (is_on_field(ny, nx) and f[ny][nx] == '.') {
                if (go(ny, nx, tresuare, (left_hand + rotate + 4) % 4)) return true;
            }
        }
        return false;
    };
    return go(0, 0, 0, 0);
}

int main() {
    while(true) {
        int h, w; cin >> h >> w;
        if (h == 0 and w == 0) break;
        vector<string> f(h);
        repeat (y, h) cin >> f[y];
        bool result = solve(h, w, f);
        cout << (result ? "YES" : "NO") << endl;
    }
}
```
