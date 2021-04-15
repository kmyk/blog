---
layout: post
redirect_from:
  - /writeup/algo/aoj/1281/
  - /blog/2015/11/21/aoj-1281/
date: 2015-11-21T01:43:37+09:00
tags: [ "competitive", "writeup", "aoj", "icpc", "a-star", "bfs" ]
---

# AOJ 1281 The Morning after Halloween

練習会で。icpc本番の制約であれば簡単だっただろうが、aojの制約だと厳しい問題。

<!-- more -->

## [The Morning after Halloween](http://judge.u-aizu.ac.jp/onlinejudge/description.jsp?id=1281) (ICPC Asia 2007 G) {#g}

### 問題

$H \times W$の盤面($H, W \le 16$)が与えられる。各マスは壁があるか通行可能であるかのどちらかである。
外周部は全て壁であり、壁を含まない$2 \times 2$の領域はない。
ここに、$N$体($N \le 3$)のロボットの初期位置と、各々のロボットの目標位置が与えられる。
単位時間ごとにロボットを1マス移動させることができる。
複数のロボットを同時に動かしてよいが、ひとつのマスにはひとつのロボットしか存在できず、ロボットの移動が交差するような移動はできない。
ロボットを移動させて各々の目標位置に移動させるために必要な最小の時間を求めよ。
目標位置に移動させられることは保証されている。

### 解説

取り得る状態の数は$(H \times W)^3$で抑えられ、壁の数が多いことから、おおよそ$10^6$程度と見積もれる。
icpcの本番においては手元で実行して提出する形式であったようであるから、単にbfsをすれば間に合ったであろう。
しかしaojにおいては時間、空間共に制限が厳しく、単にbfsをすればTLEもMLEもしてしまう。特にTLEは回避が難しい。

そこでA\*法を用いて探索を行う。評価関数としては、各々のロボットの現在位置から目標位置への最短経路の長さの最大値を用いれば通すことができた。
ただし、精度を上げるための因子として、経過時間に係数を掛けて足す必要があった。

### 実装

$N = 1,2$の場合は盤面を拡張し、ロボット`b`,`c`を壁の中に埋めてしまうと楽であった。

``` c++
#include <iostream>
#include <array>
#include <vector>
#include <cctype>
#include <map>
#include <queue>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;

struct point_t {
    int y, x;
};
point_t operator + (point_t const & a, point_t const & b) {
    return (point_t){ a.y + b.y, a.x + b.x };
}
bool operator == (point_t const & a, point_t const & b) {
    return make_pair(a.y, a.x) == make_pair(b.y, b.x);
}
bool operator < (point_t const & a, point_t const & b) {
    return make_pair(a.y, a.x) < make_pair(b.y, b.x);
}
static point_t dp[5] = { {-1,0}, {1,0}, {0,1}, {0,-1}, {0,0} };

struct state_t {
    array<point_t,3> a;
    int cost;
    int dist;
};
#define MAGIC_WEIGHT 1.3
bool operator < (state_t const & a, state_t const & b) {
    return MAGIC_WEIGHT * a.cost + a.dist > MAGIC_WEIGHT * b.cost + b.dist;
}
bool is_valid_move(int i, int j, array<point_t,3> const & s, array<point_t,3> const & t) {
    if (t[i] == t[j]) return false;
    if (t[i] == s[j] and t[j] == s[i]) return false;
    return true;
}

int main() {
    while (true) {
        int w, h, n; cin >> w >> h >> n; cin.ignore();
        if (w == 0 and h == 0 and n == 0) break;
        assert (1 <= n and n <= 3);
        vector<string> c(h);
        repeat (i,h) getline(cin, c[i]);

        array<point_t,3> start;
        array<point_t,3> goal;
        c.push_back(c.back());
        c.push_back(c.back());
        c.push_back(c.back());
        h += 3;
        if (n < 2) { c[h-3][1] = '.'; start[1] = goal[1] = { h-3, 1 }; } // b
        if (n < 3) { c[h-2][2] = '.'; start[2] = goal[2] = { h-2, 2 }; } // c
        map<point_t,int> ix;
        repeat (y,h) repeat (x,w) {
            if (islower(c[y][x])) {
                start[c[y][x] - 'a'] = { y, x };
            } else if (isupper(c[y][x])) {
                goal[c[y][x] - 'A'] = { y, x };
            }
            if (c[y][x] != '#') {
                int i = ix.size();
                ix[(point_t){ y, x }] = i;
            }
        }

        vector<vector<int> > dist[3]; // from goal
        repeat (i,3) {
            dist[i].resize(h, vector<int>(w, 1000000007));
            queue<point_t> que; // bfs
            que.push(goal[i]);
            dist[i][goal[i].y][goal[i].x] = 0;
            while (not que.empty()) {
                point_t p = que.front(); que.pop();
                repeat (j,4) {
                    auto q = p + dp[j];
                    if (c[q.y][q.x] == '#') continue;
                    if (dist[i][q.y][q.x] == 1000000007) {
                        dist[i][q.y][q.x] = dist[i][p.y][p.x] + 1;
                        que.push(q);
                    }
                }
            }
        }

        vector<vector<vector<bool> > > used(ix.size(), vector<vector<bool> >(ix.size(), vector<bool>(ix.size())));
        priority_queue<state_t> que; {
            state_t initial = { start, 0, 0 };
            repeat (i,3) initial.dist += dist[i][start[i].y][start[i].x];
            used[ix[start[0]]][ix[start[1]]][ix[start[2]]] = true;
            que.push(initial);
        }
        while (not que.empty()) {
            state_t st = que.top(); que.pop();
            array<point_t,3> & s = st.a;
            if (s == goal) {
                cout << st.cost << endl;
                break;
            }
            state_t tt = st;
            tt.cost += 1;
            array<point_t,3> & t = tt.a;
            repeat (i,5) { // a
                t[0] = s[0] + dp[i];
                if (c[t[0].y][t[0].x] == '#') continue;
                repeat (j,5) { // b
                    t[1] = s[1] + dp[j];
                    if (c[t[1].y][t[1].x] == '#') continue;
                    if (not is_valid_move(0, 1, s, t)) continue;
                    repeat (k,5) { // c
                        t[2] = s[2] + dp[k];
                        if (c[t[2].y][t[2].x] == '#') continue;
                        if (not is_valid_move(1, 2, s, t)) continue;
                        if (not is_valid_move(2, 0, s, t)) continue;
                        if (used[ix[t[0]]][ix[t[1]]][ix[t[2]]]) continue;
                        used[ix[t[0]]][ix[t[1]]][ix[t[2]]] = true;
                        tt.dist = 0;
                        repeat (i,3) tt.dist = max(tt.dist, dist[i][t[i].y][t[i].x]);
                        que.push(tt);
                    }
                }
            }
        }
    }
    return 0;
}
```
