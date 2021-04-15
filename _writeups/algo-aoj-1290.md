---
layout: post
redirect_from:
  - /writeup/algo/aoj/1290/
  - /blog/2015/11/09/aoj-1290/
date: 2015-11-09T21:28:16+09:00
tags: [ "competitive", "writeup", "aoj", "icpc", "dice", "dijkstra" ]
---

# AOJ 1290 Traveling Cube

チーム練習で見た問題。
風邪やら下痢やらしてたので後で復習する問題のstackがやばい。

<!-- more -->

## [Traveling Cube](http://judge.u-aizu.ac.jp/onlinejudge/description.jsp?id=1290) (ICPC Asia 2008 F) {#f}

### 問題

色付きのサイコロがある。6面全て異なる色である。
盤面が与えられる。盤のマスは6マスを除いて白か黒に塗られている。残るマスはサイコロの面の色で塗られていて、全て異なる色である。
この盤上でサイコロを転がしていく。
初期位置は指定される。
サイコロは黒いマスを通れない。
色の付いたマスは、指定された順にそれぞれ一度しか通れず、通る際にサイコロの上面がそのマスの色と一致していなければならない。
色の付いたマスを全て巡れるか、巡れるなら最短何手か答えよ。

### 解法

盤面の大きさ$H \times W$が$H, W \le 30$である。
このため可能な状態数は、`y座標 * x座標 * サイコロ上面の色 * サイコロ側面の回転 * 通った色付きマスの数`であり$30 \cdot 30 \cdot 6 \cdot 4 \cdot 6 = 129600$と小さい。
素直にdijkstraを書けば通る。

### 実装

サイコロの全面に名前付けて冗長に持っておくと扱い易いと気付いた。

``` c++
#include <iostream>
#include <vector>
#include <set>
#include <queue>
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define repeat(i,n) repeat_from(i,0,n)
using namespace std;
struct state_t {
    int cost;
    int y, x;
    char top, bottom, north, south, east, west;
    int used;
};
bool operator < (state_t const & a, state_t const & b) {
    return a.cost > b.cost; // for priority_queue
}
uint32_t pack(state_t const & a) {
    return (((a.y * 100 + a.x) * 100 + (a.top - 'a')) * 100 + (a.north - 'a')) * 10 + a.used;
}
int main() {
    while (true) {
        int w, h; cin >> w >> h;
        if (w == 0 and h == 0) break;
        vector<vector<char> > c(h, vector<char>(w));
        repeat (y,h) repeat (x,w) cin >> c[y][x];
        string v; cin >> v;
        // dijkstra
        priority_queue<state_t> q;
        repeat (y,h) {
            repeat (x,w) {
                if (c[y][x] == '#') {
                    c[y][x] = 'w';
                    q.push((state_t){ 0, y, x, 'r', 'c', 'g', 'm', 'b', 'y', 0 });
                }
                if (not q.empty()) break;
            }
            if (not q.empty()) break;
        }
        int result = -1;
        set<uint32_t> used;
        while (not q.empty()) {
            state_t s = q.top(); q.pop();
            if (used.count(pack(s))) continue;
            used.insert(pack(s));
            if (s.used == 6) {
                result = s.cost;
                break;
            }
            repeat (i,4) {
                state_t t = s;
                t.cost += + 1;
                constexpr int dy[] = { -1, 1, 0, 0 };
                constexpr int dx[] = { 0, 0, 1, -1 };
                t.y += dy[i];
                t.x += dx[i];
                if (t.y < 0 or h <= t.y or t.x < 0 or w <= t.x) continue;
                switch (i) {
                    case 0: // go north
                        t.top    = s.south;
                        t.north  = s.top;
                        t.bottom = s.north;
                        t.south  = s.bottom;
                        break;
                    case 1: // go south
                        t.top    = s.north;
                        t.north  = s.bottom;
                        t.bottom = s.south;
                        t.south  = s.top;
                        break;
                    case 2: // go east
                        t.top    = s.west;
                        t.west   = s.bottom;
                        t.bottom = s.east;
                        t.east   = s.top;
                        break;
                    case 3: // go west
                        t.top    = s.east;
                        t.west   = s.top;
                        t.bottom = s.west;
                        t.east   = s.bottom;
                        break;
                }
                if (c[t.y][t.x] == 'w') {
                    if (used.count(pack(t))) continue;
                    q.push(t);
                } else if (c[t.y][t.x] == v[s.used] and t.top == c[t.y][t.x]) {
                    t.used += 1;
                    if (used.count(pack(t))) continue;
                    q.push(t);
                }
            }
        }
        if (result == -1) {
            cout << "unreachable" << endl;
        } else {
            cout << result << endl;
        }
    }
    return 0;
}
```
