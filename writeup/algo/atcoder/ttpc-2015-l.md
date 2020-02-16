---
layout: post
alias: "/blog/2016/09/07/ttpc-2015-l/"
date: "2016-09-07T00:13:38+09:00"
tags: [ "competitive", "writeup", "ttpc", "atcoder", "graph", "flow", "minimum-cut", "maximam-flow", "ford-fulkerson" ]
"target_url": [ "https://beta.atcoder.jp/contests/ttpc2015/tasks/ttpc2015_l" ]
---

# 東京工業大学プログラミングコンテスト2015 L - グラフ色ぬり

## solution

最大流。アルゴリズムによるがford fulkersonを使って$O((A+B)AB)$で間に合う。

赤辺だけからなるグラフ$G'$にその最大流の流量を保ったまま何本青辺を追加できるかという問題と言える。
全部の青辺を追加したグラフ$G$の最小カットで青辺を使う数が最小のものが構成できれば、それに含まれるもの以外の青辺は全部追加できることになる。
このような最小カット中の青辺の数$x$を調べる。そのような数$x$を使って答え$\rm{ans} = A+B - x$である。

単純に、$G, G'$のそれぞれの最小カットの大きさの差$\rm{mincut}(G) - \rm{mincut}(G')$を$x$とすることを考える。
これはできない。入力例$5$が反例。これは、最大流で見たときに、ある赤色の辺を含む増加パスが複数考えられ、それぞれ違う青色の辺を使用する場合である。
そのような青色の辺は全て禁止されるべきであるが、赤色の辺がひとつだけであるためにboundされ、それらの青色の辺の内のひとつのみしか考慮されていない。
では赤色の辺の容量を増やし、全ての青色の辺の増加パスが計上されるようにすればよい。
つまり、適当な十分大きい$k$を取って、グラフ$G$中の赤色の辺の容量を$1$でなく$k$にしたグラフ$H$を作り、$x = \rm{mincut}(H) - k \cdot \rm{mincut}(G')$とすればよい。
これで通る。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <limits>
#include <functional>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;

struct edge_t { int to, cap, rev; };
int maximum_flow_destructive(int s, int t, vector<vector<edge_t> > & g) { // ford fulkerson, O(EF)
    int n = g.size();
    vector<bool> used(n);
    function<int (int, int)> dfs = [&](int i, int f) {
        if (i == t) return f;
        used[i] = true;
        for (edge_t & e : g[i]) {
            if (used[e.to] or e.cap <= 0) continue;
            int nf = dfs(e.to, min(f, e.cap));
            if (nf > 0) {
                e.cap -= nf;
                g[e.to][e.rev].cap += nf;
                return nf;
            }
        }
        return 0;
    };
    int result = 0;
    while (true) {
        used.clear(); used.resize(n);
        int f = dfs(s, numeric_limits<int>::max());
        if (f == 0) break;
        result += f;
    }
    return result;
}
void add_edge(vector<vector<edge_t> > & g, int from, int to, int cap) {
    g[from].push_back((edge_t) {   to, cap, int(g[  to].size()    ) });
    g[  to].push_back((edge_t) { from,   0, int(g[from].size() - 1) });
}
int maximum_flow(int s, int t, vector<vector<edge_t> > g /* adjacency list */) { // ford fulkerson, O(FE)
    return maximum_flow_destructive(s, t, g);
}


int main() {
    int n, a, b; cin >> n >> a >> b;
    vector<vector<edge_t> > g(n);
    vector<vector<edge_t> > h(n);
    repeat (i,a) {
        int x, y; cin >> x >> y; -- x; -- y;
        add_edge(g, x, y, 1);
        add_edge(h, x, y, b+1);
    }
    repeat (i,b) {
        int x, y; cin >> x >> y; -- x; -- y;
        add_edge(h, x, y, 1);
    }
    int ans = a+b - (maximum_flow(0, n-1, h) - (b+1) * maximum_flow(0, n-1, g));
    cout << ans << endl;
    return 0;
}
```
