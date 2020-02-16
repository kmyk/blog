---
layout: post
redirect_from:
  - /blog/2016/05/01/hackerrank-world-codesprint-april-move-the-coins/
date: 2016-05-01T12:21:08+09:00
tags: [ "competitive", "writeup", "hackerrank", "world-codesprint", "nim", "grundy-number", "game", "tree" ]
"target_url": [ "https://www.hackerrank.com/contests/world-codesprint-april/challenges/move-the-coins" ]
---

# HackerRank World Codesprint April: Move the Coins

解くのに時間かかったのくやしい

## problem

その各々の頂点にコインが複数枚置かれた根付き木の上で行われるゲームがある。
$2$人のプレイヤーがおり、交互に以下の操作を繰り返し、操作ができなくなったプレイヤーの負けである。

-   コインが存在する根でない頂点$v$を選ぶ。$v$のコインを$1$枚以上の好きなだけ、$v$の親に選んだコインを移す。

始めにそのような木が与えられる。
以下のクエリを処理せよ。

-   頂点$u, v$が指示される。頂点$u$の親を$v$に変更した後の木における必勝手番を答えよ。
    -   ただし、処理の結果が木にならない場合は、そう答えよ。
    -   各々のクエリは独立である。副作用はない。

## solution

Grundy number. It can be $O(N + Q \log N)$.

The first player win iff $\Sigma\_{v \in V}^{\text{xor}} (c_v \cdot d_v)$ is positive, where $d_v$ is the depth of the node $v$, the $d\_{\rm{root}} = 0$.
So you should only calculate it.

## implementation

To detect a cycle, I used $O(N)$ simple algorithm so this is $O(NQ)$.
If you dislike this complexity order, you can use doubling, in this case also known as lowest common ancestor algorithm.

``` c++
#include <iostream>
#include <vector>
#include <functional>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
const int root = 0;
int main() {
    // input tree
    int n; cin >> n;
    vector<int> c(n); repeat (i,n) cin >> c[i];
    vector<vector<int> > g(n);
    repeat (i,n-1) {
        int a, b; cin >> a >> b; -- a; -- b;
        g[a].push_back(b);
        g[b].push_back(a);
    }
    // prepare
    vector<int> p(n); {
        function<void (int, int)> dfs = [&](int i, int prv) {
            p[i] = prv;
            for (int j : g[i]) if (j != p[i]) dfs(j, i);
        };
        dfs(root, -1);
    }
    vector<int> depth(n, -1); {
        depth[root] = 0;
        function<int (int)> rec = [&](int i) {
            if (depth[i] == -1) depth[i] = rec(p[i]) + 1;
            return depth[i];
        };
        repeat (i,n) rec(i);
    }
    vector<int> even(n), odd(n); { // in the subtree, in such a depth, does an effective coin exist
        function<void (int)> dfs = [&](int i) {
            even[i] ^= c[i];
            for (int j : g[i]) if (j != p[i]) {
                dfs(j);
                odd[i] ^= even[j];
                even[i] ^= odd[j];
            }
        };
        dfs(root);
    }
    // output
    int queries; cin >> queries;
    while (queries --) {
        int u, v; cin >> u >> v; -- u; -- v;
        int i = v;
        while (i != root and i != u) i = p[i];
        if (i == u) { // cycle found
            cout << "INVALID" << endl;
        } else {
            int ans = odd[root];
            if (depth[u] % 2 == 1) { // remove
                ans ^= even[u];
            } else {
                ans ^= odd[u];
            }
            if ((depth[v] + 1) % 2 == 1) { // add
                ans ^= even[u];
            } else {
                ans ^= odd[u];
            }
            cout << (ans ? "YES" : "NO") << endl;
        }
    }
    return 0;
}
```
