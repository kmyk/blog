---
layout: post
redirect_from:
  - /writeup/algo/atcoder/agc_009_d/
  - /writeup/algo/atcoder/agc-009-d/
  - /blog/2017/12/31/agc-009-d/
date: "2017-12-31T18:51:22+09:00"
tags: [ "competitive", "writeup", "atcoder", "graph", "tree" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc009/tasks/agc009_d" ]
---

# AtCoder Grand Contest 009: D - Uninity

分からなかった。しばらく寝かせてから再び見たときも分からなかった。

## solution

解法はeditorialに任せ、どうすれば辿り着けるかを検討したい。
区切りは以下の$4$点だろう。1,4は分かるが、しかし2,3はどうすればいいのか分からない。

1.  各頂点にそれが中心として足されたときのウニ度の値を書き込む
2.  木の頂点への書き込みがウニ度である iff 同じ数$i$が書かれた任意の異なる$2$頂点間のpath上に$i + 1$以上の数が書かれた頂点がある
3.  木DPをする。適当に根を決めて葉側から頂点に書き込んでいく。書き込む数は貪欲に、つまりその位置で下を見て見える数を列挙しその[mex](https://en.wikipedia.org/wiki/Mex_\(mathematics\))
4.  見える数の管理は集合のbit表現でやると楽

## implementation

``` c++
#include <cstdio>
#include <functional>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
using namespace std;

int main() {
    // input
    int n; scanf("%d", &n);
    vector<vector<int> > g(n);
    repeat (i, n - 1) {
        int a, b; scanf("%d%d", &a, &b); -- a; -- b;
        g[a].push_back(b);
        g[b].push_back(a);
    }
    // solve
    function<int (int, int)> go = [&](int i, int parent) {
        int cnt1 = 0, cnt2 = 0;
        for (int j : g[i]) if (j != parent) {
            int q = go(j, i);
            cnt2 |= cnt1 & q;
            cnt1 |= q;
        }
        int p = 1;
        while (p <= cnt2 or cnt1 & p) p <<= 1;
        return (cnt1 & ~ (p - 1)) | p;
    };
    int p = go(0, -1);
    int k = 31 - __builtin_clz(p);
    // output
    printf("%d\n", k);
    return 0;
}
```
