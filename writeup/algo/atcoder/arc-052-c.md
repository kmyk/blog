---
layout: post
redirect_from:
  - /blog/2016/05/20/arc-052-c/
date: 2016-05-20T21:56:25+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "dijkstra" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc052/tasks/arc052_c" ]
---

# AtCoder Regular Contest 052 C - 高橋くんと不思議な道

## solution

dijkstra。前処理等は不要で、ただ回すだけでよい。$O((N^2+M)\log N)$ではあるが十分速い。

木の頂点$v$に今までに使ったタイプBの道の数$b$を乗せて、$N\times N$個の頂点$(v,b)$の上でdijkstraをする。
この際、明らかに不要な頂点の使用は行わないようにする。
つまり、$(v,b)$へ至るコスト$d\_{v,b}$が、$d\_{v,b} \le d\_{v,b+k}$となるような頂点$(v,b+k)$への遷移は行わないようにする。

空間を$N^2$で確保すると、速度的には問題はないが、MLEとなる。
dijkstraのloop中で動的に拡張する。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <queue>
#include <tuple>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
struct state_t { int v, used, cost; };
bool operator < (state_t a, state_t b) { return make_tuple(- a.cost, - a.used, a.v) < make_tuple(- b.cost, - b.used, b.v); }
const int inf = 1e9+7;
int main() {
    int n, m; cin >> n >> m;
    vector<vector<vector<int> > > g(2, vector<vector<int> >(n));
    repeat (i,m) {
        int c, a, b; cin >> c >> a >> b;
        g[c][a].push_back(b);
        g[c][b].push_back(a);
    }
    vector<vector<int> > dp(n, vector<int>(1, inf));
    priority_queue<state_t> que; {
        state_t s = { 0, 0, 0 };
        dp[0][0] = 0;
        que.push(s);
    }
    while (not que.empty()) {
        state_t s = que.top(); que.pop();
        if (dp[s.v][s.used] < s.cost) continue;
        repeat (c,2) {
            for (int w : g[c][s.v]) {
                state_t t;
                t.v = w;
                t.used = s.used + (c ? 1 : 0);
                t.cost = s.cost + 1 + (c ? s.used : 0);
                if (t.used >= n) continue;
                auto it = min_element(dp[t.v].begin(), dp[t.v].begin() + min<int>(t.used+1, dp[t.v].size()));
                if (it != dp[t.v].end() and *it <= t.cost) continue;
                if (dp[t.v].size() <= t.used) dp[t.v].resize(t.used + 1, inf);
                dp[t.v][t.used] = t.cost;
                que.push(t);
            }
        }
    }
    repeat (i,n) {
        cout << *min_element(dp[i].begin(), dp[i].end()) << endl;
    }
    return 0;
}
```
