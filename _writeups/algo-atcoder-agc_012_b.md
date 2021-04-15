---
layout: post
redirect_from:
  - /writeup/algo/atcoder/agc_012_b/
  - /writeup/algo/atcoder/agc-012-b/
  - /blog/2017/06/14/agc-012-b/
date: "2017-06-14T11:27:32+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc", "graph", "bfs" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc012/tasks/agc012_b" ]
---

# AtCoder Grand Contest 012: B - Splatter Painting

## solution

クエリを後ろから処理し積極的に枝刈りする。$D = \max d\_i \le 10$の制約から$O(Q + (N + M) D)$で間に合う。

それぞれの頂点で、その頂点$v$から距離$d$以内の頂点が全て塗られているような値$d\_v$を(保守的に)持たせておく。
これはその頂点に(直接あるいは間接的に)来たクエリの値を覚えておくだけ。
後ろから処理していくので、覚えている距離$d\_v$よりクエリの値$d\_i$が小さいならその場で打ち切れる。
打ち切られずに処理が走るのは高々$\max d\_i$回だけなので、これは計算量を落とす。

## implementation

``` c++
#include <cstdio>
#include <queue>
#include <tuple>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_reverse(i, n) for (int i = (n)-1; (i) >= 0; --(i))
using namespace std;

int main() {
    // input
    int n, m; scanf("%d%d", &n, &m);
    vector<vector<int> > g(n);
    repeat (i, m) {
        int a, b; scanf("%d%d", &a, &b); -- a; -- b;
        g[a].push_back(b);
        g[b].push_back(a);
    }
    int q; scanf("%d", &q);
    vector<int> v(q), d(q), c(q); repeat (t, q) { scanf("%d%d%d", &v[t], &d[t], &c[t]); -- v[t]; }
    // solve
    vector<int> result(n);
    vector<int> used(n, -1);
    repeat_reverse (t, q) {
        queue<int> que;
        auto push = [&](int i, int dist) {
            if (used[i] < dist) {
                used[i] = dist;
                if (not result[i]) result[i] = c[t];
                que.emplace(i);
            }
        };
        push(v[t], d[t]);
        while (not que.empty()) {
            int i = que.front(); que.pop();
            if (used[i] != 0) {
                for (int j : g[i]) {
                    push(j, used[i]-1);
                }
            }
        }
    }
    // output
    repeat (i, n) {
        printf("%d\n", result[i]);
    }
    return 0;
}
```
