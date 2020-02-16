---
layout: post
date: 2018-09-14T02:59:41+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "divide-and-conquer", "partial-persistent", "undo" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc040/tasks/arc040_d" ]
redirect_from:
  - /writeup/algo/atcoder/arc-040-d/
---

# AtCoder Regular Contest 040: D - カクカク塗り

<!-- {% raw %} -->

## 解法

ゴールの位置を分割統治っぽく二分探索。
undo可能にすると計算量は$O(N^2 \log N)$のはず。

ゴールの位置をどこかに仮定すれば、その判定は明らか。
スタートでもゴールでもない空のマスは接続性を伝播させるので端から埋めていけてそれぞれ$O(N^2)$。
しかしゴールの位置を全探索すると全体では$O(N^4)$。
そこでゴールの位置を少しずつ絞り込んでいくようにして操作をまとめる。
盤面の左半分にゴールがあると仮定すれば右半分はすべて処理してしまえるので、そのようにして再帰的にやる。

## メモ

-   想定解は$O(N^3)$

## 実装

``` c++
#include <algorithm>
#include <array>
#include <cassert>
#include <iostream>
#include <stack>
#include <tuple>
#include <vector>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < (int)(n); ++ (i))
#define ALL(x) begin(x), end(x)
using namespace std;
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

enum {
    RIGHT = 0,
    UP = 1,
    LEFT = 2,
    DOWN = 3,
};
const int dy[4] = { 0, -1, 0, +1 };
const int dx[4] = { +1, 0, -1, 0 };

class solver {
    const int n;
    vector<string> const & f;

    int sy, sx;
    int obstacles;

    vector<vector<array<char, 4> > > conn;
    stack<pair<int, int> > stk;
    vector<vector<bool> > pushed;
    stack<vector<tuple<int, int, int, char> > > preserved;

public:

    solver(int n_, vector<string> const & f_)
            : n(n_), f(f_) {
        conn = vectors(n, n, array<char, 4>({{ '?', '?', '?', '?' }}));
        pushed = vectors(n, n, false);
        obstacles = 0;
        REP (y, n) REP (x, n) {
            if (f[y][x] == 's') {
                sy = y;
                sx = x;
            } else if (f[y][x] == '#') {
                ++ obstacles;
            }
        }
    }

private:

    bool is_on_field(int y, int x) const {
        return 0 <= y and y < n and 0 <= x and x < n;
    }

    void push(int y, int x) {
        if (pushed[y][x]) return;
        if (not count(ALL(conn[y][x]), '?')) return;
        stk.emplace(y, x);
        pushed[y][x] = true;
    }

    void set(int y, int x, int dir, char value) {
        if (value == '?') {
            // nop
        } else if (conn[y][x][dir] == value) {
            // nop
        } else if (conn[y][x][dir] == '?') {
            if (not preserved.empty()) {
                preserved.top().emplace_back(y, x, dir, conn[y][x][dir]);
            }
            conn[y][x][dir] = value;
            int ny = y + dy[dir];
            int nx = x + dx[dir];
            int ndir = (dir + 2) % 4;
            if (is_on_field(ny, nx)) {
                if (conn[ny][nx][ndir] != value) {
                    push(ny, nx);
                }
            } else {
                if (value == '.') throw false;
            }
        } else {
            throw false;
        }
    }

public:

    void preserve() {
        assert (stk.empty());
        preserved.emplace();
    }

    void undo() {
        while (not stk.empty()) {
            int y, x; tie(y, x) = stk.top();
            stk.pop();
            pushed[y][x] = false;
        }
        for (auto it : preserved.top()) {
            int y, x; char dir, value; tie(y, x, dir, value) = it;
            conn[y][x][dir] = value;
        }
        preserved.pop();
    }

    void fetch(int ly, int lx, int ry, int rx) {
        REP3 (y, ly, ry) REP3 (x, lx, rx) {
            push(y, x);
        }
    }

    void flush(int ly, int lx, int ry, int rx) {
        while (not stk.empty()) {
            int y, x; tie(y, x) = stk.top();
            stk.pop();
            pushed[y][x] = false;

            // wall
            if (x + 1 >= n) set(y, x, RIGHT, '#');
            if (y - 1 <  0) set(y, x,    UP, '#');
            if (x - 1 <  0) set(y, x,  LEFT, '#');
            if (y + 1 >= n) set(y, x,  DOWN, '#');

            // copy neighbors
            if (x + 1 <  n) set(y, x, RIGHT, conn[y][x + 1][ LEFT]);
            if (y - 1 >= 0) set(y, x,    UP, conn[y - 1][x][ DOWN]);
            if (x - 1 >= 0) set(y, x,  LEFT, conn[y][x - 1][RIGHT]);
            if (y + 1 <  n) set(y, x,  DOWN, conn[y + 1][x][   UP]);

            // obstacle
            if (f[y][x] == '#') {
                set(y, x, RIGHT, '#');
                set(y, x,    UP, '#');
                set(y, x,  LEFT, '#');
                set(y, x,  DOWN, '#');
            }

            // empty
            if (f[y][x] == '.') {
                if (conn[y][x][ LEFT] == '.' and conn[y][x][RIGHT] == '.') throw false;
                if (conn[y][x][ DOWN] == '.' and conn[y][x][   UP] == '.') throw false;
                if (conn[y][x][RIGHT] == '.' and conn[y][x][ LEFT] == '.') throw false;
                if (conn[y][x][   UP] == '.' and conn[y][x][ DOWN] == '.') throw false;
                if (not (ly <= y and y < ry and lx <= x and x < rx)) {
                    if (conn[y][x][ LEFT] == '#') set(y, x, RIGHT, '.');
                    if (conn[y][x][ DOWN] == '#') set(y, x,    UP, '.');
                    if (conn[y][x][RIGHT] == '#') set(y, x,  LEFT, '.');
                    if (conn[y][x][   UP] == '#') set(y, x,  DOWN, '.');
                    if (conn[y][x][ LEFT] == '.') set(y, x, RIGHT, '#');
                    if (conn[y][x][ DOWN] == '.') set(y, x,    UP, '#');
                    if (conn[y][x][RIGHT] == '.') set(y, x,  LEFT, '#');
                    if (conn[y][x][   UP] == '.') set(y, x,  DOWN, '#');
                }
            }

            // start
            if (f[y][x] == 's') {
                int empty = 0;
                int obstacle = 0;
                REP (dir, 4) {
                    empty    += (conn[y][x][dir] == '.');
                    obstacle += (conn[y][x][dir] == '#');
                }
                if (empty   >= 2) throw false;
                if (obstacle == 4) throw false;
                if (empty == 1) {
                    REP (dir, 4) if (conn[y][x][dir] == '?') {
                        set(y, x, dir, '#');
                    }
                }
                if (obstacle == 3) {
                    REP (dir, 4) if (conn[y][x][dir] == '?') {
                        set(y, x, dir, '.');
                    }
                }
            }
        }
    }

    bool chase() const {
        int cnt = obstacles;
        int y = sy, x = sx;
        int py = -1, px = -1;
        while (true) {
            ++ cnt;
            bool found = false;
            REP (dir, 4) if (conn[y][x][dir] == '.') {
                int ny = y + dy[dir];
                int nx = x + dx[dir];
                if (not (ny == py and nx == px)) {
                    py = y;
                    px = x;
                    y = ny;
                    x = nx;
                    found = true;
                    break;
                }
            }
            if (not found) break;
        }
        return cnt == n * n;
    }
};

bool solve1(int n, solver & s, int ly, int lx, int ry, int rx) {
    if (ry - ly == 0) return false;
    if (rx - lx == 0) return false;
    if (ry - ly == 1 and rx - lx == 1) {
        s.preserve();
        try {
            s.fetch(ly, lx, ry, rx);
            s.flush(ly, lx, ry, rx);
            if (s.chase()) return true;
        } catch (bool e) {
            if (e) return true;
        }
        s.undo();
    } else if (rx - lx < ry - ly) {
        int my = (ly + ry) / 2;
        s.preserve();
        try {
            s.fetch(my, lx, ry, rx);
            s.flush(ly, lx, my, rx);
            if (solve1(n, s, ly, lx, my, rx)) return true;
        } catch (bool e) {
            if (e) return true;
        }
        s.undo();
        s.preserve();
        try {
            s.fetch(ly, lx, my, rx);
            s.flush(my, lx, ry, rx);
            if (solve1(n, s, my, lx, ry, rx)) return true;
        } catch (bool e) {
            if (e) return true;
        }
        s.undo();
    } else {
        int mx = (lx + rx) / 2;
        s.preserve();
        try {
            s.fetch(ly, mx, ry, rx);
            s.flush(ly, lx, ry, mx);
            if (solve1(n, s, ly, lx, ry, mx)) return true;
        } catch (bool e) {
            if (e) return true;
        }
        s.undo();
        s.preserve();
        try {
            s.fetch(ly, lx, ry, mx);
            s.flush(ly, mx, ry, rx);
            if (solve1(n, s, ly, mx, ry, rx)) return true;
        } catch (bool e) {
            if (e) return true;
        }
        s.undo();
    }
    return false;
}

bool solve(int n, vector<string> const & f) {
    try {
        solver s(n, f);
        s.fetch(0, 0, n, n);
        s.flush(0, 0, n, n);
        return solve1(n, s, 0, 0, n, n);
    } catch (bool e) {
        return e;
    }
}

int main() {
    int n; cin >> n;
    vector<string> f(n);
    REP (y, n) cin >> f[y];
    cout << (solve(n, f) ? "POSSIBLE" : "IMPOSSIBLE") << endl;
    return 0;
}
```

<!-- {% endraw %} -->
