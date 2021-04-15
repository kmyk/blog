---
layout: post
redirect_from:
  - /writeup/algo/atcoder/agc_011_c/
  - /writeup/algo/atcoder/agc-011-c/
  - /blog/2017/03/13/agc-011-c/
date: "2017-03-13T00:29:16+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc", "graph", "bipartite-graph" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc011/tasks/agc011_c" ]
---

# AtCoder Grand Contest 011: C - Squared Graph

Dを優先してほぼ手を付けなかったが、解けていてもよい問題だった。

## solution

連結成分への分解と奇閉路の検出をして、その数を元に計算。$O(N + M)$。

元のグラフ上で互いに到達不能な頂点同士は、積グラフ上でも互いに到達不能な頂点群を生む。
よって、元のグラフを連結成分に分解してその対ごとに考えてよい。
次のように問題を読み替えられる:
連結グラフ$G_i$ ($0 \le i \lt k$)が与えられるので、各$(i, j)$について積グラフ$G_i \times G_j$の頂点数を数え、その総和を答えよ。

連結グラフ$G, H$をとる。
$G, H, G \times H$の頂点数をそれぞれ$x, y, z$とする。
$x = 1$または$y = 1$である場合は辺が$1$本も生まれないので $z = xy$。
それ以外の場合では、$G, H$は共に連結なので$z \in \\{ 1, 2 \\}$になる。
$x = y = 2$の場合の積グラフが縦横に並ぶものと考えればそうなる。
ここで$z = 1$となるのは$G, H$のどちらかが奇閉路を持つとき。
つまり、それぞれのグラフを以下のように分類すれば十分:

1.  $\|V\| = 1$
2.  $\|V\| \ge 2$ かつ 奇閉路がない
3.  $\|V\| \ge 2$ かつ 奇閉路がある

奇閉路の存在は二部グラフ性と同値なので、連結成分への分解の際にまとめてやるとよい。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <queue>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
using ll = long long;
using namespace std;
int main() {
    // input
    int n, m; cin >> n >> m;
    vector<vector<int> > g(n);
    repeat (i,m) {
        int u, v; cin >> u >> v; -- u; -- v;
        g[u].push_back(v);
        g[v].push_back(u);
    }
    // decompose
    int a_components = 0, a_nodes = 0; // connected graph: |V|  = 1
    int b_components = 0, b_nodes = 0; // connected graph: |V| >= 2 and no odd cyles
    int c_components = 0, c_nodes = 0; // connected graph: |V| >= 2 and odd cycles exist
    vector<char> used(n);
    repeat (root,n) if (not used[root]) {
        bool is_bipartite = true;
        int size = 0;
        queue<int> que;
        que.push(root);
        used[root] = 'A';
        while (not que.empty()) {
            int i = que.front(); que.pop();
            ++ size;
            for (int j : g[i]) {
                if (used[j]) {
                    if (used[i] == used[j]) is_bipartite = false;
                } else {
                    used[j] = (used[i] == 'A' ? 'B' : 'A');
                    que.push(j);
                }
            }
        }
        if (size == 1) {
            ++ a_components; a_nodes += size;
        } else if (is_bipartite) {
            ++ b_components; b_nodes += size;
        } else {
            ++ c_components; c_nodes += size;
        }
    }
    // calculate
    ll ans = 0;
    ans += a_nodes *(ll) a_nodes; // A A
    ans += 2 * a_nodes *(ll) b_nodes; // A B ; B A
    ans += 2 * a_nodes *(ll) c_nodes; // A C ; C A
    ans += b_components *(ll) b_components * 2; // B B
    ans += 2 * b_components *(ll) c_components; // B C ; C B
    ans += c_components *(ll) c_components; // C C
    // output
    cout << ans << endl;
    return 0;
}
```
