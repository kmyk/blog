---
redirect_from:
  - /writeup/algo/topcoder/srm-736-medium/
layout: post
date: 2018-08-16T02:18:40+09:00
tags: [ "competitive", "writeup", "topcoder", "srm", "graph", "clique" ]
---

# TopCoder SRM 736 Div1 Medium: MinDegreeSubgraph

## solution

clique $K _ {k + 1}$ がlocally k-denseで辺数が最小のもの。
clique $K _ {k - 1}$ とそれ以外の頂点の間に辺を張って完全2部グラフを作るのが、locally k-denseでなく辺数が最大のもの(たぶん)。
$m$をこれと比較する。
$O(1)$。

証明はまだ分かっていません。

## note

-   コメントに微妙に嘘を混ぜたまま提出してしまった
-   他の人のコードを開いたら自分のと違ってたので落胆してたが、周囲がどんどんhackされていった

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
typedef long long ll;
using namespace std;
class MinDegreeSubgraph { public: string exists(ll n, ll m, ll k); };

const string ALL = "ALL";
const string SOME = "SOME";
const string NONE = "NONE";
ll binom_2(ll n) { return n * (n - 1) / 2; }
string MinDegreeSubgraph::exists(ll n, ll m, ll k) {
    if (k == 0) return ALL;
    if (n < k + 1) return NONE;

    // a clique K_{k + 1}
    bool is_none = binom_2(k + 1) > m;

    // make a graph like complete bipartite one between a clique K_{k - 1} and all other vertices
    bool is_all = binom_2(k - 1) + (k - 1) * (n - k + 1) < m;

    assert (not (is_none and is_all));
    return is_none ? NONE : is_all ? ALL : SOME;
}
```
