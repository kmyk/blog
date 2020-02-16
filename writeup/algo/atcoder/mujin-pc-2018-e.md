---
layout: post
date: 2018-08-05T01:03:33+09:00
tags: [ "competitive", "writeup", "atcoder", "mujin-pc", "dijkstra" ]
"target_url": [ "https://beta.atcoder.jp/contests/mujin-pc-2018/tasks/mujin_pc_2018_e" ]
---

# Mujin Programming Challenge 2018: E - 迷路

## solution

Dijkstra法。
各時刻$t$と各向き$d$について次にその向きに移動できるような最小の時刻$t' \ge t$を求めておく。
$O(NM \log (NM))$。

## note

-   素直に見ると時刻によって辺の重みが動的に変化しているように見えるが、時刻ごとに$NM$個の頂点を持つ無限有向グラフの上で重み$0$の辺に関して最適化を入れいていると解釈することもできる。
-   `priority_queue` の優先度の向きのことを忘れていてたくさんWAを生やした。その裏でoverflowもしてた気がする。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define REP_R(i, n) for (int i = int(n) - 1; (i) >= 0; -- (i))
#define ALL(x) begin(x), end(x)
using ll = long long;
using namespace std;
template <class T> using reversed_priority_queue = priority_queue<T, vector<T>, greater<T> >;
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

const int dy[] = { -1, 1, 0, 0 };
const int dx[] = { 0, 0, 1, -1 };
int from_dir(char c) { return c == 'U' ? 0 : c == 'D' ? 1 : c == 'R' ? 2 : c == 'L' ? 3 : -1; }
bool is_on_field(int y, int x, int h, int w) { return 0 <= y and y < h and 0 <= x and x < w; }

ll solve(int h, int w, int k, string const & d, vector<string> const & f) {
    // make a lookup table for directions
    vector<array<int, 4> > next(k);
    fill(ALL(next[0]), INT_MAX);
    REP_R (t, k) {
        next[t] = next[t == k - 1 ? 0 : t + 1];
        next[t][from_dir(d[t])] = t;
    }
    REP (t, k) {
        REP (i, 4) if (next[t][i] != INT_MAX) {
            next[t][i] += k;
        }
    }
    REP_R (t, k) {
        next[t] = next[t == k - 1 ? 0 : t + 1];
        next[t][from_dir(d[t])] = t;
    }
    REP (t, k) {
        REP (i, 4) if (next[t][i] != INT_MAX) {
            next[t][i] -= t;
        }
    }

    // find the start point
    int sy = -1, sx = -1;
    REP (y, h) REP (x, w) {
        if (f[y][x] == 'S') {
            sy = y;
            sx = x;
        }
    }

    // do Dijkstra algorithm
    reversed_priority_queue<tuple<ll, int, int> > que;
    auto dist = vectors(h, w, LLONG_MAX);
    que.emplace(0, sy, sx);
    dist[sy][sx] = 0;
    while (not que.empty()) {
        ll t; int y, x; tie(t, y, x) = que.top();
        que.pop();
        if (t != dist[y][x]) continue;
        if (f[y][x] == 'G') {
            return t;
        }
        REP (i, 4) {
            if (next[t % k][i] == INT_MAX) continue;
            ll nt = t + next[t % k][i] + 1;
            int ny = y + dy[i];
            int nx = x + dx[i];
            if (not is_on_field(ny, nx, h, w)) continue;
            if (f[ny][nx] == '#') continue;
            if (dist[ny][nx] <= nt) continue;
            que.emplace(nt, ny, nx);
            dist[ny][nx] = nt;
        }
    }
    return -1;
}

int main() {
    // input
    int h, w, k; cin >> h >> w >> k;
    string d; cin >> d;
    vector<string> f(h);
    REP (y, h) cin >> f[y];

    // solve
    ll ans = solve(h, w, k, d, f);

    // output
    cout << ans << endl;
    return 0;
}
```
