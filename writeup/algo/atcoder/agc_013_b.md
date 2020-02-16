---
layout: post
redirect_from:
  - /writeup/algo/atcoder/agc-013-b/
  - /blog/2017/08/09/agc-013-b/
date: "2017-08-09T23:13:43+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc", "graph", "construction" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc013/tasks/agc013_b" ]
---

# AtCoder Grand Contest 013: B - Hamiltonish Path

出力を$1$-basedにするのを忘れて$1$WA。サンプルと単純比較では検証できないタイプの問題だったので気付けなかった。

## solution

適当な頂点から始めて伸ばせる限り単純パスを伸ばして、伸ばせなくなったら答え。$O(N + M)$。
単純パスを伸ばせないということはその端点に隣接する頂点が全てパスに含まれているということであるので。

## implementation

``` c++
#include <algorithm>
#include <cassert>
#include <cstdio>
#include <functional>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define whole(x) begin(x), end(x)
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
    // solve
    vector<bool> used(n);
    vector<int> path;
    function<void (int)> go = [&](int i) {
        path.push_back(i);
        used[i] = true;
        for (int j : g[i]) if (not used[j]) {
            go(j);
            break;
        }
    };
    go(0);
    reverse(whole(path));
    assert (path.back() == 0);
    used[0] = false;
    path.pop_back();
    go(0);
    // output
    printf("%d\n", int(path.size()));
    repeat (i, path.size()) {
        printf("%d%c", path[i] + 1, i + 1 == path.size() ? '\n' : ' ');
    }
    return 0;
}
```
