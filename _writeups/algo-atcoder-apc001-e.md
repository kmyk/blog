---
redirect_from:
  - /writeup/algo/atcoder/apc001-e/
layout: post
date: 2018-07-13T14:52:40+09:00
tags: [ "competitive", "writeup", "atcoder", "tree" ]
"target_url": [ "https://beta.atcoder.jp/contests/apc001/tasks/apc001_e" ]
---

# AtCoder Petrozavodsk Contest 001: E - Antennas on Tree

## solution

極端な例としてstar graphを眺め(典型)てるとなにか見えてくるのでいい感じにやる。$O(N)$。

$1$点の周囲に$n$点生えたstar graph $S_n$を考えると、必要なアンテナは$n - 1$本である。
$S_n$と$S_m$を適当な葉で繋ぐと、必要なアンテナは$n + m - 1$本。
一般に部分グラフとしてstar $S_n$を含むと、その周囲でおよそ$n - 1$本要求される。
また逆に、そのような部分グラフ以外はアンテナの本数にあまり影響しない。
具体的には次数$2$の頂点はすべて縮約してしまってよく、位相的な性質だけ考えればよいことが分かる。
そんな感じで次数$3$以上の頂点とその接続関係だけを抜き出してみよう。
これができれば雰囲気で立つ簡単な式で答えが求まる。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
using namespace std;

int solve(int n, const vector<vector<int> > & g) {
    vector<vector<int> > h(n);
    function<int (int, int, int)> go = [&](int i, int parent, int ancestor) {
        if (g[i].size() == 1) {
            return -1;
        } else if (g[i].size() == 2) {
            for (int j : g[i]) if (j != parent) {
                return go(j, i, ancestor);
            }
            assert (false);
        } else {
            if (ancestor != -1) {
                h[i].push_back(ancestor);
            }
            for (int j : g[i]) if (j != parent) {
                int k = go(j, i, i);
                if (k != -1) {
                    h[i].push_back(k);
                }
            }
            return i;
        }
    };

    assert (n >= 2);
    int root = 0;
    while (root < n and g[root].size() < 3) {
        ++ root;
    }
    if (root == n) {
        return 1;
    }
    go(root, -1, -1);

    int cnt = 0;
    REP (i, n) if (g[i].size() >= 3) {
        cnt += max(0, (int)g[i].size() - (int)h[i].size() - 1);
    }
    return cnt;
}

int main() {
    // input
    int n; cin >> n;
    vector<vector<int> > g(n);
    REP (i, n - 1) {
        int a, b; cin >> a >> b;
        g[a].push_back(b);
        g[b].push_back(a);
    }

    // solve
    int answer = solve(n, g);

    // output
    cout << answer << endl;
    return 0;
}
```
