---
layout: post
redirect_from:
  - /blog/2016/05/31/srm-691-easy/
date: 2016-05-31T01:46:05+09:00
tags: [ "competitive", "writeup", "srm", "topcoder", "graph" ]
---

# TopCoder SRM 691 Div1 Easy: Sunnygraphs

I solved this a bit quickly, and I could update my highest rating.

## problem

$N$頂点で出次数が全て$1$であるような有向グラフが与えられる。
頂点の部分集合$M$で、以下の一連の操作をした後に頂点$0,1$が辺の向きを無視して連結になるような$M$の数を数えよ。

1.  頂点$n$を追加する
2.  $v \in M$に関して、それから出る辺の行き先を頂点$n$にする

## solution

Think the directed chain from $0,1$ and the intersection. $O(N)$.

You can notice that: vertices which are not connected to both vertices $0,1$, are trivial.
Also, vertices which is not able to be reached from both $0,1$ with the directed edges, can be ignored.
You should consider only the two chains, one from the vertex $0$ and one from the vertex $1$.

Let the length of the two chains be $l_0, l_1$, and the number of vertices which are in the both chains be $c$.
Then the answer is now $\rm{ans} = f(l_0, l_1, c) \cdot 2^{n - l_0 - l_1 + c}$.

To calculate the $f(l_0, l_1, c)$, do case analysis.

When two chains become equivalent, this becomes trivial: $f(l_0, l_1, c) = 2^{l_0 + l_1 - c} = 2^c$.

![](/blog/2016/05/31/srm-691-easy/d.svg)

When there are no intersections, there must be some vertices of $M$ in both chains. Therefore, $f(l_0, l_1, 0) = (2^{l_0} - 1) \cdot (2^{l_1} - 1)$.

![](/blog/2016/05/31/srm-691-easy/b.svg)

When one chain includes another chain properly: if there are some vertices of $M$ in the non-intersected part of including chain, there must be some vertices of $M$ in the incensed one.
The constraint is only this, and $f(l_0, l_1, c) = (2^{l_0 - c} - 1) \cdot 2^{l_1} + 1 \cdot 2^{l_1}$ (when the chain $0$ includes the chain $1$, $l_1 = c$).

![](/blog/2016/05/31/srm-691-easy/c.svg)

The other cases, the chains are splitted into three parts.
If the central part has vertices of $M$, other vertices has no constraints.
Else, the central part has no vertices of $M$, the chains both has no vertices of $M$ or both has vertices of $M$.
$f(l_0, l_1, c) = (2^c - 1) \cdot 2^{l_0 - c} \cdot 2^{l_1 - c} + 1 \cdot (1 \cdot 1 + (2^{l_0 - c} - 1) \cdot (2^{l_1 - c} - 1))$.

![](/blog/2016/05/31/srm-691-easy/a.svg)


## implementation

``` c++
#include <bits/stdc++.h>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;
class Sunnygraphs { public: ll count(vector<int> const & a); };

vector<int> connected_vertices(vector<int> const & g, int root) {
    vector<int> acc;
    for (int v = root; find(acc.begin(), acc.end(), v) == acc.end(); v = g[v]) {
        acc.push_back(v);
    }
    return acc;
}
ll Sunnygraphs::count(vector<int> const & a) {
    int n = a.size();
    vector<int> zeros = connected_vertices(a, 0);
    vector<int> ones  = connected_vertices(a, 1);
    vector<int> common;
    repeat (i,n) {
        if (find(zeros.begin(), zeros.end(), i) != zeros.end()
                and find(ones.begin(), ones.end(), i) != ones.end()) {
            common.push_back(i);
        }
    }
    int z =  zeros.size();
    int o =   ones.size();
    int c = common.size();
    if (common.empty()) {
        return ((1ll << z) - 1) * ((1ll << o) - 1) * (1ll << (n - z - o + c));
    } else {
        bool zero_in_ones = find( ones.begin(),  ones.end(), 0) !=  ones.end();
        bool one_in_zeros = find(zeros.begin(), zeros.end(), 1) != zeros.end();
        if (zero_in_ones and one_in_zeros) {
            return (1ll << (z + o - c)) * (1ll << (n - z - o + c));
        } else if (zero_in_ones) {
            return (((1ll << (o - c)) - 1) * ((1ll << z) - 1) + 1 * (1ll << z)) * (1ll << (n - z - o + c));
        } else if (one_in_zeros) {
            return (((1ll << (z - c)) - 1) * ((1ll << o) - 1) + 1 * (1ll << o)) * (1ll << (n - z - o + c));
        } else {
            return (((1ll << c) - 1) * (1ll << (o - c + z - c)) + 1 * (1 * 1 + ((1ll << (z - c)) - 1) * ((1ll << (o - c)) - 1))) * (1ll << (n - z - o + c));
        }
    }
}
```
