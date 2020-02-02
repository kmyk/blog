---
layout: post
alias: "/blog/2016/02/27/mujin-pc-2016-c/"
title: "MUJIN プログラミングチャレンジ C - オレンジグラフ / Orange Graph"
date: 2016-02-27T23:48:23+09:00
tags: [ "competitive", "writeup", "atcoder", "mujin-pc", "graph", "bipartite-graph" ]
---

非想定解で無理矢理に通したがその分時間を取られた。

## [C - オレンジグラフ / Orange Graph](https://beta.atcoder.jp/contests/mujin-pc-2016/tasks/mujin_pc_2016_c)

### 解法

奇数長の閉路がないグラフとは二部グラフのことである。$2^N$個の頂点の分割全てを試し、所属の異なる頂点間を結ぶ辺を全て使用する。この辺集合の高々$2^N$個のそれぞれが極大になっているかを、それ以外の$2^N-1$組と比較することにより判定。$O(2^N)$。

想定解はunion-find木を使って$M$回の操作で極大性のあたりを上手くやるもの。

### 実装

`bitset`の列のsortってどうすればよかったの？

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <bitset>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define repeat_from_reverse(i,m,n) for (int i = (n)-1; (i) >= (m); --(i))
typedef long long ll;
using namespace std;
typedef bitset<120> edge_set;
int main() {
    int n, m; cin >> n >> m;
    assert (m <= 120);
    vector<int> x(m), y(m);
    vector<vector<int> > g(n);
    repeat (i,m) {
        cin >> x[i] >> y[i]; -- x[i]; -- y[i];
        g[x[i]].push_back(y[i]);
        g[y[i]].push_back(x[i]);
    }
    vector<edge_set> es(1<<n);
    repeat (a,1<<n) {
        int b = ((1<<n)-1)&(~a);
        repeat (i,m) {
            if (!!(a&(1<<x[i])) == !!(b&(1<<y[i]))) {
                es[a].set(i);
            }
        }
    }
    {
        vector<pair<pair<ll,ll>,int> > ts(1<<n);
        edge_set mask((1ll<<60)-1);
        repeat (i,1<<n) ts[i] = { { (es[i] >> 60).to_ullong(), (es[i] & mask).to_ullong() }, i };
        sort(ts.begin(), ts.end());
        vector<edge_set> us;
        us.push_back(es[ts[0].second]);
        repeat_from (i,1,1<<n) if (ts[i-1].first != ts[i].first) us.push_back(es[ts[i].second]);
        es = us;
    }
    int l = es.size();
    int ans = 0;
    repeat (i,l) {
        bool is_maximum = true;
        repeat_from_reverse (j,i+1,l) {
            if ((es[i]&(~es[j])).none()) {
                is_maximum = false;
                break;
            }
        }
        if (is_maximum) ans += 1;
    }
    cout << ans << endl;
    return 0;
}
```
