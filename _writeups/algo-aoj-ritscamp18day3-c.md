---
layout: post
redirect_from:
  - /writeup/algo/aoj/ritscamp18day3-c/
  - /blog/2018/04/02/aoj-ritscamp18day3-c/
date: "2018-04-02T22:46:48+09:00"
tags: [ "competitive", "writeup", "aoj", "rupc", "graph", "bfs" ]
"target_url": [ "https://onlinejudge.u-aizu.ac.jp/beta/room.html#RitsCamp18Day3/problems/C" ]
---

# AOJ RitsCamp18Day3: C. AA グラフ (AA Graph)

## solution

英大文字から `o` `-` `|` だけを通って直進し英大文字が見つかれば辺を張る。
後はBFSなりWarshall-Floydなりをする。
$O(HW)$。

## note

-   editorial: <https://www.slideshare.net/hcpc_hokudai/rupc-2018-day3-c-aa-aa-graph>
-   bfs貼ったけどwarshall floydでもよかったなあと後から気付きました

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
using namespace std;

const int dy[] = { -1, 1, 0, 0 };
const int dx[] = { 0, 0, 1, -1 };
const char *type = "||--";
vector<vector<int> > parse(int h, int w, vector<string> const & f) {
    auto is_on_field = [&](int y, int x) { return 0 <= y and y < h and 0 <= x and x < w; };
    vector<vector<int> > g(26);
    REP (y, h) REP (x, w) if (isupper(f[y][x])) {
        REP (i, 4) {
            int ny = y + dy[i];
            int nx = x + dx[i];
            while (is_on_field(ny, nx) and (f[ny][nx] == 'o' or f[ny][nx] == type[i])) {
                ny += dy[i];
                nx += dx[i];
            }
            if (is_on_field(ny, nx) and isupper(f[ny][nx])) {
                g[f[y][x] - 'A'].push_back(f[ny][nx] - 'A');
            }
        }
    }
    return g;
}

vector<int> breadth_first_search(int root, vector<vector<int> > const & g) {
    int n = g.size();
    vector<int> dist(n, INT_MAX);
    queue<int> que;
    dist[root] = 0;
    que.push(root);
    while (not que.empty()) {
        int i = que.front(); que.pop();
        for (int j : g[i]) if (dist[j] == INT_MAX) {
            dist[j] = dist[i] + 1;
            que.push(j);
        }
    }
    return dist;
}

int main() {
    // input
    int h, w; cin >> h >> w;
    char start, goal; cin >> start >> goal;
    vector<string> f(h);
    REP (y, h) cin >> f[y];

    // solve
    vector<vector<int> > g = parse(h, w, f);
    vector<int> dist = breadth_first_search(start - 'A', g);
    int result = dist[goal - 'A'];

    // output
    cout << result << endl;
    return 0;
}
```
