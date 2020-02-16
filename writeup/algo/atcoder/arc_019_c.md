---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc-019-c/
  - /blog/2015/10/08/arc-019-c/
date: 2015-10-08T23:59:59+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "dijkstra", "shortest-path" ]
---

# AtCoder Regular Contest 019 C - 最後の森

一日一問がそろそろつらい。ARCのC問題を全完したら止めようかなという思いがある。

<!-- more -->

## [C - 最後の森](https://beta.atcoder.jp/contests/arc019/tasks/arc019_3) {#c}

さっぱり分からなかったので[答え](http://www.slideshare.net/chokudai/arc019)を見ました。

### 問題

最短路の長さを求める。ただし、途中でほこらのあるマスを通り、かつ敵の居るマスは一定種類までしか通れない。

### 解法

愚直に計算しようとすると明らかに間に合わない。
倒した敵の種類の状態は$2^{RC}$個ある。これを保持しないことを考える。
敵の情報の種類が必要になるのは、一度通ったマスを再度通るかもしれないからである。
そこで、考える歩道を、交わらないいくつかの道に分割するようなことを考える。
特に、スタートから分岐点、分岐点からほこら、ほこらから分岐点への帰りは同じ道を使い、分岐点からゴール、という風に分割する。
こうしておけば、スタート、ほこら、ゴールのそれぞれから分岐点までの最短路を倒す敵の数ごとに計算し、それらの組み合わせを計算することで、多項式時間で解が得られる。

### 実装

``` c++
#include <iostream>
#include <vector>
#include <queue>
#include <algorithm>
#include <cassert>
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define repeat(i,n) repeat_from(i,0,n)
template <class T>
using reversed_priority_queue = std::priority_queue<T, std::vector<T>, std::greater<T> >;
using namespace std;
struct state_t { int y, x; int k; int l; };
bool operator > (state_t const & a, state_t const & b) { return make_pair(a.l, a.k) > make_pair(b.l, b.k); }
const int dy[4] = { -1, 1, 0, 0 };
const int dx[4] = { 0, 0, 1, -1 };
vector<vector<vector<int> > > dijkstra(int r, int c, int k, vector<vector<char> > const & s, int y, int x) {
    vector<vector<vector<int> > > result(r, vector<vector<int> >(c, vector<int>(k+1, -1)));
    reversed_priority_queue<state_t> q;
    q.push({ y, x, 0, 0 });
    while (not q.empty()) {
        state_t t = q.top(); q.pop();
        if (result[t.y][t.x][t.k] != -1) continue;
        result[t.y][t.x][t.k] = t.l;
        repeat (i,4) {
            int ny = t.y + dy[i];
            int nx = t.x + dx[i];
            if (not (0 <= ny and ny < r and 0 <= nx and nx < c)) continue;
            if (s[ny][nx] == 'T') continue;
            int nk = t.k + (s[ny][nx] == 'E' ? 1 : 0);
            if (k < nk) continue;
            if (result[ny][nx][nk] != -1) continue;
            q.push({ ny, nx, nk, t.l+1 });
        }
    }
    return result;
}
int main() {
    int r, c, k; cin >> r >> c >> k;
    vector<vector<char> > s(r, vector<char>(c));
    int sy, sx, cy, cx, gy, gx;
    repeat (y,r) repeat (x,c) {
        cin >> s[y][x];
        if (s[y][x] == 'S') { sy = y; sx = x; }
        if (s[y][x] == 'C') { cy = y; cx = x; }
        if (s[y][x] == 'G') { gy = y; gx = x; }
    }
    vector<vector<vector<int> > > dps = dijkstra(r, c, k, s, sy, sx);
    vector<vector<vector<int> > > dpc = dijkstra(r, c, k, s, cy, cx);
    vector<vector<vector<int> > > dpg = dijkstra(r, c, k, s, gy, gx);
    int result = 1000000006;
    repeat (y,r) repeat (x,c) {
        int tk = k + (s[y][x] == 'E' ? 2 : 0);
        repeat (ks,tk+1) {
            if (dps[y][x][ks] == -1) continue;
            if (s[y][x] == 'E') assert (ks != 0);
            repeat (kc,tk-ks+1) {
                if (dpc[y][x][kc] == -1) continue;
                if (s[y][x] == 'E') assert (kc != 0);
                repeat (kg,tk-ks-kc+1) {
                    if (dpg[y][x][kg] == -1) continue;
                    if (s[y][x] == 'E') assert (kg != 0);
                    result = min(result, dps[y][x][ks] + 2 * dpc[y][x][kc] + dpg[y][x][kg]);
                }
            }
        }
    }
    if (result == 1000000006) result = -1;
    cout << result << endl;
    return 0;
}
```
