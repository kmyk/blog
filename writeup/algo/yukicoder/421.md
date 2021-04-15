---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/421/
  - /blog/2016/09/10/yuki-421/
date: "2016-09-10T00:22:17+09:00"
tags: [ "competitive", "writeup", "yukicoder", "flow", "bipartite-matching" ]
"target_url": [ "http://yukicoder.me/problems/no/421" ]
---

# Yukicoder No.421 しろくろチョコレート

典型/知識ゲーではという声があったが、(私は過去に見た記憶がないので)よかった。

## solution

二部マッチング。$O(N^2M^2)$で通る。

まず、$2 \times 1$の形をいくつ作れるかに帰着する。
$2 \times 1$がただで作れるなら作って損をしない、白と黒がひとつずつ減るので他に影響しない、あたりから言える。

$2 \times 1$の形をいくつ作れるかであるが、これは二部マッチング。
editorialにいい感じの図があるので見て。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <limits>
#include <functional>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
template <typename T, typename X> auto vectors(T a, X x) { return vector<T>(x, a); }
template <typename T, typename X, typename Y, typename... Zs> auto vectors(T a, X x, Y y, Zs... zs) { auto cont = vectors(a, y, zs...); return vector<decltype(cont)>(x, cont); }

struct edge_t { int to, cap, rev; };
int maximum_flow_destructive(int s, int t, vector<vector<edge_t> > & g) { // ford fulkerson, O(EF)
    int n = g.size();
    vector<bool> used(n);
    function<int (int, int)> dfs = [&](int i, int f) {
        if (i == t) return f;
        used[i] = true;
        for (edge_t & e : g[i]) {
            if (used[e.to] or e.cap <= 0) continue;
            int nf = dfs(e.to, min(f, e.cap));
            if (nf > 0) {
                e.cap -= nf;
                g[e.to][e.rev].cap += nf;
                return nf;
            }
        }
        return 0;
    };
    int result = 0;
    while (true) {
        used.clear(); used.resize(n);
        int f = dfs(s, numeric_limits<int>::max());
        if (f == 0) break;
        result += f;
    }
    return result;
}
void add_edge(vector<vector<edge_t> > & g, int from, int to, int cap) {
    g[from].push_back((edge_t) {   to, cap, int(g[  to].size()    ) });
    g[  to].push_back((edge_t) { from,   0, int(g[from].size() - 1) });
}

const int dy[4] = { -1, 1, 0, 0 };
const int dx[4] = { 0, 0, 1, -1 };

int main() {
    // input
    int h, w; cin >> h >> w;
    vector<vector<bool> > f = vectors(false, h, w);
    repeat (y,h) repeat (x,w) {
        char c; cin >> c;
        f[y][x] = c != '.';
    }
    // compute
    auto is_on_field = [&](int y, int x) { return 0 <= y and y < h and 0 <= x and x < w; };
    vector<vector<edge_t> > g(h * w + 2);
    auto index = [&](int y, int x) { return y * w + x; };
    const int src = h * w;
    const int dst = h * w + 1;
    int white = 0, black = 0;
    repeat (y,h) repeat (x,w) {
        if (not f[y][x]) continue;
        if (y % 2 == x % 2) {
            white += 1;
            add_edge(g, src, index(y, x), 1);
            repeat (i,4) {
                int ny = y + dy[i];
                int nx = x + dx[i];
                if (not is_on_field(ny, nx)) continue;
                if (not f[ny][nx]) continue;
                add_edge(g, index(y, x), index(ny, nx), 1);
            }
        } else {
            black += 1;
            add_edge(g, index(y, x), dst, 1);
        }
    }
    int flow = maximum_flow_destructive(src, dst, g);
    int ans = 0;
    ans += flow * 100;
    ans += (min(white, black) - flow) * 10;
    ans += (max(white, black) - (min(white, black) - flow) - flow);
    // output
    cout << ans << endl;
    return 0;
}
```
