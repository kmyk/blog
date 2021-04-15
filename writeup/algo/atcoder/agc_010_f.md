---
layout: post
redirect_from:
  - /writeup/algo/atcoder/agc_010_f/
  - /writeup/algo/atcoder/agc-010-f/
  - /blog/2017/08/12/agc-010-f/
date: "2017-08-12T00:39:48+09:00"
tags: [ "competitive", "writeup", "tree", "game" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc010/tasks/agc010_f" ]
---

# AtCoder Grand Contest 010: F - Tree Game

後輩が$700$点ぐらいだって言ってた。そう聞いてから解いたらそうだった。

## solution

有向木にして始点ごとにDFS。$O(N^2)$。メモ化すれば$O(N)$だが不要。

頂点$i - j$が隣接していて$A\_i \le A\_j$だとしよう。
駒が$i$にあるときに$j$に動かすと、相手の番で$i$に戻されて$A\_i-1 \le A\_j-1$という状況になる。
これは繰り返せば自分が負ける。
つまり駒を石の数の減少する方向に動かせなければ負け。
逆に$A\_i \gt A\_j$であれば(相手が$i$に駒を戻すなら)これは勝ちとなる。

よって辺$i - j$を$A\_i, A\_j$の比較によって向きを付け、交互に動かして葉に辿り付いた方が負け。
これは$O(N)$のDFSで解ける。
始点については総当たりしても間に合う。

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
    vector<int> a(n); repeat (i, n) scanf("%d", &a[i]);
    vector<vector<int> > g(n);
    repeat (i, n - 1) {
        int x, y; scanf("%d%d", &x, &y); -- x; -- y;
        g[x].push_back(y);
        g[y].push_back(x);
    }
    // solve
    function<bool (int)> go = [&](int i) {
        for (int j : g[i]) if (a[i] > a[j]) {
            if (not go(j)) {
                return true;
            }
        }
        return false;
    };
    vector<int> result;
    repeat (i, n) if (a[i]) {
        if (go(i)) {
            result.push_back(i);
        }
    }
    // output
    repeat (i, result.size()) {
        printf("%d%c", result[i] + 1, i + 1 == result.size() ? '\n' : ' ');
    }
    return 0;
}
```
