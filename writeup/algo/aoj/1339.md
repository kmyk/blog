---
layout: post
redirect_from:
  - /writeup/algo/aoj/1339/
  - /blog/2017/12/04/aoj-1339/
date: "2017-12-04T10:53:28+09:00"
tags: [ "competitive", "writeup", "aoj", "icpc", "icpc-asia", "dijkstra" ]
"target_url": [ "http://judge.u-aizu.ac.jp/onlinejudge/description.jsp?id=1339" ]
---

# AOJ 1339. Dragon's Cruller

愚直書くだけの典型という感じがするが、そうは感じない人もいるっぽい？
ゲームAI系のコンテストの経験の差だろうか。

## solution

Dijkstra法。状態数は$9! = 362880$と少ないので$O(E \log V)$で間に合う。

## implementation

``` c++
#include <array>
#include <cstdio>
#include <queue>
#include <tuple>
#include <unordered_map>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_reverse(i, n) for (int i = (n)-1; (i) >= 0; --(i))
using namespace std;
const int dy[] = { -1, 1, 0, 0 };
const int dx[] = { 0, 0, 1, -1 };

int pack(array<array<int, 3>, 3> const & d) {
    int acc = 0;
    repeat (y, 3) {
        repeat (x, 3) {
            acc = acc * 10 + d[y][x];
        }
    }
    return acc;
}
tuple<array<array<int, 3>, 3>, int, int> unpack(int acc) {
    array<array<int, 3>, 3> d;
    int zy = -1, zx = -1;
    repeat_reverse (y, 3) {
        repeat_reverse (x, 3) {
            d[y][x] = acc % 10;
            acc /= 10;
            if (d[y][x] == 0) {
                zy = y;
                zx = x;
            }
        }
    }
    return make_tuple(d, zy, zx);
}

int main() {
    while (true) {
        // input
        int ch, cv; scanf("%d%d", &ch, &cv);
        if (ch == 0 and cv == 0) break;
        array<array<int, 3>, 3> start, goal;
        repeat (y, 3) repeat (x, 3) scanf("%d", &start[y][x]);
        repeat (y, 3) repeat (x, 3) scanf("%d", &goal[y][x]);
        // solve
        unordered_map<int, int> used;
        priority_queue<pair<int, int> > que;
        used[pack(start)] = 0;
        que.emplace(0, pack(start));
        int pack_goal = pack(goal);
        while (not que.empty()) {
            int c, s; tie(c, s) = que.top(); que.pop();
            c *= -1;
            if (used[s] < c) continue;
            if (s == pack_goal) break;
            array<array<int, 3>, 3> d; int y, x; tie(d, y, x) = unpack(s);
            repeat (i, 4) {
                int nx = x + dx[i];
                int cy = 0;
                if (nx == -1) {
                    nx = 2;
                    cy = -1;
                }
                if (nx == 3) {
                    nx = 0;
                    cy = 1;
                }
                int ny = (y + dy[i] + cy + 3) % 3;
                swap(d[y][x], d[ny][nx]);
                int ns = pack(d);
                swap(d[y][x], d[ny][nx]);
                int nc = c + (i < 2 ? cv : ch);
                if (not used.count(ns) or nc < used[ns]) {
                    used[ns] = nc;
                    que.emplace(- nc, ns);
                }
            }
        }
        // output
        printf("%d\n", used[pack_goal]);
    }
    return 0;
}
```
