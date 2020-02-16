---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc-045-c/
  - /blog/2015/11/03/arc-045-c/
date: 2015-11-03T19:57:20+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "tree", "xor", "path", "dfs" ]
---

# AtCoder Regular Contest 045 C - エックスオア多橋君

分からなかったので解答を見た。どちらかというと難しいと感じた。

<!-- more -->

## [C - エックスオア多橋君](https://beta.atcoder.jp/contests/arc045/tasks/arc045_c) {#c}

### 問題

非負整数の重みが付いた木が与えられる。この木の上の長さが$1$以上の道で、道上の重みの排他的論理和による総和が$x$であるものの数を答えよ。

### 解説

排他的論理和の性質を使う。
根から頂点$a,b$への重みの排他的論理和を取ると、ふたつの道の共通部分が打ち消しあい、頂点$a,b$間の道の重みが得られる。

適当に決めた根から、全ての頂点への道を考え、その重みを数えるのは$O(n)$。
重みのそれぞれに関して、排他的論理和を取って$X$になるような重みを見つけるのは、$a \oplus b = x \iff a \oplus x = b$と変形すれば$O(\log n)$。

$O(n \log n)$。

### 実装

長さ$0$の道は許されていないのに注意。

``` c++
#include <iostream>
#include <vector>
#include <map>
#include <cstdint>
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define repeat(i,n) repeat_from(i,0,n)
typedef long long ll;
using namespace std;
struct edge_t { int to; uint32_t cost; };
void dfs(int v, int p, uint32_t value, vector<vector<edge_t> > const & g, map<uint32_t,ll> & acc) {
    acc[value] += 1;
    for (auto e : g[v]) if (e.to != p) {
        dfs(e.to, v, value ^ e.cost, g, acc);
    }
}
int main() {
    int n; uint32_t x; cin >> n >> x;
    vector<vector<edge_t> > g(n);
    repeat (i,n-1) {
        int x, y; uint32_t c; cin >> x >> y >> c;
        -- x; -- y;
        g[x].push_back((edge_t){ y, c });
        g[y].push_back((edge_t){ x, c });
    }
    map<uint32_t,ll> acc;
    dfs(0, -1, 0, g, acc);
    ll result = 0;
    for (auto it : acc) {
        if (it.first < (it.first ^ x)) {
            result += acc[it.first ^ x] * it.second;
        } else if (it.first == (it.first ^ x)) { // means x == 0
            result += it.second * (it.second - 1) / 2;
        }
    }
    cout << result << endl;
    return 0;
}
```

### 参考

-   [AtCoder Regular Contest 045 解説](http://www.slideshare.net/chokudai/arc045)
