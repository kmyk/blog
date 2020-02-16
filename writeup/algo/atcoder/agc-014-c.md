---
layout: post
alias: "/blog/2017/05/07/agc-014-c/"
date: "2017-05-07T21:10:44+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc", "bfs" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc014/tasks/agc014_c" ]
---

# AtCoder Grand Contest 014: C - Closed Rooms

誤読。問題文が多少難しいとはいえ、A問題ぐらいには簡単だし$700$点でなくて$300$点でよさそう。

## solution

$1$回目の魔法では開いた部屋しか移動できない。$2$回目以降の魔法では直前の魔法で通る部屋を開いておくことで、任意の部屋を移動可能。
そのようにBFSなりをする。$O(HW)$。

## implementation

BFS部分がコピペで汚らしい。距離と$K$を比較して分岐する、$2$回目以降は最短経路つまり直線しか移動しないのでBFSしない、などすれば綺麗になるはず。

``` c++
#include <cstdio>
#include <vector>
#include <queue>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
using namespace std;
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }
const int dy[] = { -1, 1, 0, 0 };
const int dx[] = { 0, 0, 1, -1 };
struct point_t { int y, x; };
const int inf = 1e9+7;

int main() {
    // input
    int h, w, k; scanf("%d%d%d", &h, &w, &k);
    auto closed = vectors(h, w, bool());
    point_t start;
    repeat (y,h) repeat (x,w) {
        char c; scanf(" %c", &c);
        closed[y][x] = c == '#';
        if (c == 'S') {
            start.y = y;
            start.x = x;
        }
    }
    // solve
    point_t goal = { -1, -1 };
    auto is_on_field = [&](int y, int x) { return 0 <= y and y < h and 0 <= x and x < w; };
    auto is_goal = [&](int y, int x) { return y == 0 or y == h-1 or x == 0 or x == w-1; };
    auto dist = vectors(h, w, inf);
    { // // bfs
        queue<point_t> que;
        dist[start.y][start.x] = 0;
        que.push(start);
        while (not que.empty()) {
            point_t p = que.front(); que.pop();
            if (is_goal(p.y, p.x)) {
                goal = p;
                break;
            }
            if (dist[p.y][p.x] == k) continue;
            repeat (i,4) {
                point_t q = p;
                q.y += dy[i];
                q.x += dx[i];
                if (not is_on_field(q.y, q.x)) continue;
                if (closed[q.y][q.x]) continue;
                if (dist[q.y][q.x] <= dist[p.y][p.x] + 1) continue;
                dist[q.y][q.x] = dist[p.y][p.x] + 1;
                que.push(q);
            }
        }
    }
    // // bfs
    if (goal.y == -1) {
        queue<point_t> que;
        repeat (y,h) repeat (x,w) {
            if (dist[y][x] != inf) {
                dist[y][x] = k;
                que.push((point_t) { y, x });
            }
        }
        while (not que.empty()) {
            point_t p = que.front(); que.pop();
            if (is_goal(p.y, p.x)) {
                goal = p;
                break;
            }
            repeat (i,4) {
                point_t q = p;
                q.y += dy[i];
                q.x += dx[i];
                if (not is_on_field(q.y, q.x)) continue;
                if (dist[q.y][q.x] <= dist[p.y][p.x] + 1) continue;
                dist[q.y][q.x] = dist[p.y][p.x] + 1;
                que.push(q);
            }
        }
    }
    // output
    assert (goal.y != -1);
    int result = (dist[goal.y][goal.x] + k - 1) / k;
    printf("%d\n", result);
    return 0;
}
```
