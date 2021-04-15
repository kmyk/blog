---
layout: post
redirect_from:
  - /writeup/algo/atcoder/agc_018_d/
  - /writeup/algo/atcoder/agc-018-d/
  - /blog/2017/07/23/agc-018-d/
date: "2017-07-23T23:19:15+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc", "tree", "centroid", "hamiltonian-path" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc018/tasks/agc018_d" ]
---

# AtCoder Grand Contest 018: D - Tree and Hamilton Path

後輩氏が「木の重心を求める方法が分からなかったので解けなかった」と言っていた。そこ以外は分かっていたようなのでプロみを感じた。

## solution

完全グラフなどと言っているが無視してよい。それぞれの辺を何回通れるかを考える。
自明な上界 $-$ 重心(の全て)に隣接する辺のひとつの重み、が答え。
自明な上界とは各辺ごとに次を足し合わせたもの: 左右の部分木の大きさを考えその最小値と重みと$2$を掛けたもの。
木なので重心は$1$個あるいは$2$個。
前者ならそれに隣接する辺の中で最も軽い辺、後者の場合はそれらの間の唯一の辺。$O(N)$。

細かい話は[解説放送](https://www.youtube.com/watch?v=2sGEmgWVd6k)が分かりやすかったのでそれに任せたい。
LCAを持ってくるのが上手い。

## 反省

本番中では通せなかったが、自明な上界から何らかの辺ひとつの重みを引けばよいだろうというのまでなら推測できていた。
愚直解は簡単に書けるので書いていたので、どの辺が引かれているのかを可視化して眺めるべきだった。
木の可視化ライブラリが必要。

## implementation

``` c++
#include <cassert>
#include <cstdio>
#include <functional>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
using ll = long long;
using namespace std;
template <class T> inline void setmax(T & a, T const & b) { a = max(a, b); }
template <class T> inline void setmin(T & a, T const & b) { a = min(a, b); }

constexpr int inf = 1e9+7;
int main() {
    int n; scanf("%d", &n);
    vector<vector<pair<int, int> > > g(n);
    repeat (i, n - 1) {
        int a, b, c; scanf("%d%d%d", &a, &b, &c); -- a; -- b;
        g[a].emplace_back(b, c);
        g[b].emplace_back(a, c);
    }
    vector<int> size(n);
    ll result = 0;
    int offset = inf;
    int centroid = -1;
    int min_centroid_weight = inf;
    function<void (int, int)> go = [&](int i, int parent) {
        size[i] = 1;
        int centroid_weight = 0;
        for (auto edge : g[i]) {
            int j, edge_weight; tie(j, edge_weight) = edge;
            if (j == parent) continue;
            go(j, i);
            size[i] += size[j];
            int s = min(size[j], n - size[j]);
            result += edge_weight * 2ll * s;
            if (2 * s == n) {
                offset = edge_weight;
            }
            setmax(centroid_weight, size[j]);
        }
        setmax(centroid_weight, n - size[i]);
        if (centroid_weight < min_centroid_weight) {
            min_centroid_weight = centroid_weight;
            centroid = i;
        }
    };
    go(0, -1);
    if (offset == inf) {
        for (auto edge : g[centroid]) {
            int edge_weight = edge.second;
            setmin(offset, edge_weight);
        }
    }
    result -= offset;
    printf("%lld\n", result);
    return 0;
}
```

