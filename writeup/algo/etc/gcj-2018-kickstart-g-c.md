---
redirect_from:
  - /writeup/algo/etc/gcj-2018-kickstart-g-c/
layout: post
date: 2018-10-25T15:59:13+09:00
tags: [ "competitive", "writeup", "gcj", "kickstart", "maze", "graph", "bit-dp" ]
"target_url": [ "https://codejam.withgoogle.com/codejam/contest/5374486/dashboard#s=p2" ]
---

# Google Code Jam Kickstart Round G 2018: C. Cave Escape

## 問題

$2$次元盤面上に迷路がある。
スタートからゴールまで移動したい。
体力の概念があり、罠やポーションが置いてあるマスに始めて侵入したときそれに応じて体力が増減する。
体力を負にしないようにゴールまで移動するとき、ゴールでの体力の最大値はいくつか。

## 解法

### 概要

罠の数$T \le 15$と小さいのでbit-DP。
$O(HW + 2^TT)$。
罠を連続して踏む場合や、スタートからゴールまで罠なしで移動できる場合に注意。

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < (int)(n); ++ (i))
#define ALL(x) begin(x), end(x)
using namespace std;
template <class T, class U> inline void chmax(T & a, U const & b) { a = max<T>(a, b); }
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

template <typename T> ostream & operator << (ostream & out, vector<T> const & xs) { REP (i, int(xs.size()) - 1) out << xs[i] << ' '; if (not xs.empty()) out << xs.back(); return out; }

const int dy[] = { -1, 1, 0, 0 };
const int dx[] = { 0, 0, 1, -1 };
bool is_on_field(int y, int x, int h, int w) { return 0 <= y and y < h and 0 <= x and x < w; }

constexpr int OBSTACLE = -100000;
int solve(int h, int w, int e, int start_y, int start_x, int goal_y, int goal_x, vector<vector<int> > const & f) {
    assert (f[start_y][start_x] == 0);
    assert (f[ goal_y][ goal_x] == 0);

    // connect cells
    auto room = vectors(h, w, -1);
    vector<int> traps;
    vector<int> room_score;
    function<void (int, int)> go = [&](int y, int x) {
        room_score.back() += f[y][x];
        REP (dir, 4) {
            int ny = y + dy[dir];
            int nx = x + dx[dir];
            if (not is_on_field(ny, nx, h, w)) continue;
            if (f[ny][nx] == OBSTACLE) {
                // nop
            } else if (f[ny][nx] < 0) {
                // nop
            } else {
                if (room[ny][nx] == -1) {
                    room[ny][nx] = room[y][x];
                    go(ny, nx);
                }
            }
        }
    };
    REP (y, h) REP (x, w) if (f[y][x] != OBSTACLE) {
        if (room[y][x] == -1) {
            int i = room_score.size();
            room[y][x] = i;
            room_score.push_back(0);
            if (f[y][x] >= 0) {
                go(y, x);
            } else {
                traps.push_back(i);
                room_score.back() += f[y][x];
            }
        }
    }
    int num_room = room_score.size();

    // construct graph
    vector<set<int> > g(num_room);
    REP (y, h) REP (x, w) {
        int i = room[y][x];
        if (i == -1) continue;
        REP (dir, 4) {
            int ny = y + dy[dir];
            int nx = x + dx[dir];
            if (not is_on_field(ny, nx, h, w)) continue;
            int j = room[ny][nx];
            if (j == -1) continue;
            if (i == j) continue;
            g[i].insert(j);
            g[j].insert(i);
        }
    }
    int start = room[start_y][start_x];
    int  goal = room[ goal_y][ goal_x];

    // bit dp
    int answer = -1;
    vector<int> score(1 << traps.size(), -1);
    vector<vector<int> > connected_rooms(1 << traps.size());
    score[0] = e + room_score[start];
    connected_rooms[0].push_back(start);
    if (start == goal) {
        chmax(answer, score[0]);
    }
    REP3 (edge, 1, 1 << traps.size()) {
        // choose the last trap
        REP (k, traps.size()) if (edge & (1 << k)) {
            int prev_edge = edge ^ (1 << k);
            int t = traps[k];
            int score_k = score[prev_edge] + room_score[t];
            if (score_k < 0) continue;
            bool connected = false;
            for (int j : g[t]) {
                if (binary_search(ALL(connected_rooms[prev_edge]), j)) {
                    connected = true;
                } else {
                    score_k += max(0, room_score[j]);
                }
            }
            if (not connected) continue;
            chmax(score[edge], score_k);
        }

        // update rooms
        if (score[edge] != -1) {
            auto & rooms = connected_rooms[edge];
            REP (k, traps.size()) if (edge & (1 << k)) {
                int t = traps[k];
                rooms.push_back(t);
                for (int j : g[t]) if (room_score[j] >= 0) {
                    rooms.push_back(j);
                }
            }
            sort(ALL(rooms));
            rooms.erase(unique(ALL(rooms)), rooms.end());
        }

        // update highscore
        if (binary_search(ALL(connected_rooms[edge]), goal)) {
            chmax(answer, score[edge]);
        }
    }
    return answer;
}

int main() {
    int testcase; cin >> testcase;
    REP (caseindex, testcase) {
        int h, w, e; cin >> h >> w >> e;
        int start_y, start_x; cin >> start_y >> start_x;
        -- start_y;
        -- start_x;
        int goal_y, goal_x; cin >> goal_y >> goal_x;
        -- goal_y;
        -- goal_x;
        auto f = vectors(h, w, int());
        REP (y, h) REP (x, w) cin >> f[y][x];
        int answer = solve(h, w, e, start_y, start_x, goal_y, goal_x, f);
        cout << "Case #" << caseindex + 1 << ": " << answer << endl;
        cerr << "Case #" << caseindex + 1 << ": " << answer << endl;
    }
    return 0;
}
```
