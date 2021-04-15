---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/317/
  - /blog/2016/11/25/yuki-317/
date: "2016-11-25T22:40:44+09:00"
tags: [ "competitive", "writeup", "yukicoder", "graph", "dp", "knapsack-problem" ]
"target_url": [ "http://yukicoder.me/problems/no/317" ]
---

# Yukicoder No.317 辺の追加

面白い問題だった。

## implementation

DP。成分の個数を$2$進展開してまとめる。入力がグラフなのは適当にやる。$O(N \log N + M)$。

入力がグラフなのは問題の背景を自然にするための目眩し。
連結成分に分解して、その大きさと個数の表を作る。分解は単にdfsでよい。

本題のナップサック的なDP。
各大きさについてその個数回だけtableを舐めると$O(N^2)$で間に合わない(グラフに辺がほぼない場合等)。
しかし同じ大きさに関する走査を複数回行うのは無駄がある。
例えば大きさ$1$に関する走査を$3$回分するとして、これは大きさ$2$の走査$1$回と大きさ$1$の走査$1$回をすれば同じことになる。
このようにすれば対数回の走査で済み$O(N \log N)$で間に合う。
ただし単純な$2$進数展開ではだめなことには注意。
例えば大きさ$1$の走査が$10$回分必要だとして、$10 = 2^1 + 2^3 = 2 + 8$と分解して大きさ$2,8$の走査をそれぞれ行うと、成分を$1$回しか使わない場合が落ちる。
これを解決する分解はいくらか表現の方法があるだろうが、$x = 1 + 2 + 4 + \dots + 2^k + x' \; (x' \lt 2^k)$と再帰的に$2$進展開すると楽。

## solution

``` c++
#include <iostream>
#include <vector>
#include <map>
#include <tuple>
#include <functional>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define repeat_reverse(i,n) for (int i = (n)-1; (i) >= 0; --(i))
using namespace std;
template <class T> void setmin(T & a, T const & b) { if (b < a) a = b; }
const int inf = 1e9+7;
int main() {
    // input
    int n, m; cin >> n >> m;
    vector<vector<int> > g(n);
    repeat (i,m) {
        int u, v; cin >> u >> v; -- u; -- v;
        g[u].push_back(v);
        g[v].push_back(u);
    }
    // enumerate components
    map<int,int> components; {
        vector<bool> used(n);
        function<int (int)> go = [&](int i) {
            used[i] = true;
            int acc = 1;
            for (int j : g[i]) if (not used[j]) acc += go(j);
            return acc;
        };
        repeat (i,n) if (not used[i]) {
            components[go(i)] += 1;
        }
    }
    // dp
    vector<int> dp(n+1, inf);
    dp[0] = -1;
    for (auto it : components) {
        int size, cnt; tie(size, cnt) = it;
        while (cnt) for (int k = 1; k <= cnt; cnt -= k, k *= 2) {
            repeat_reverse (i,n+1-k*size) {
                setmin(dp[i+k*size], dp[i]+k);
            }
        }
    }
    // output
    repeat_from (i,1,n+1) {
        cout << (dp[i] == inf ? -1 : dp[i]) << endl;
    }
    return 0;
}
```
