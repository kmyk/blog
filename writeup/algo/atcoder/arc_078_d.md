---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc-078-d/
  - /blog/2017/07/15/arc-078-d/
date: "2017-07-15T23:15:36+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "tree", "game" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc078/tasks/arc078_b" ]
---

# AtCoder Regular Contest 078: D - Fennec VS. Snuke

## solution

ad-hoc。
お互いにできるだけ相手に近付くように一直線に伸ばしていく。
一度黒色と白色のマスが隣接するとそれ以降はどう塗って最終的に塗れる頂点は同じ。そのような境界で黒い木と白い木の$2$本に分割されるが、どちらの色の木が大きいかが答え。
$O(N)$。

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
    vector<vector<int> > g(n);
    repeat (i, n - 1) {
        int a, b; scanf("%d%d", &a, &b); -- a; -- b;
        g[a].push_back(b);
        g[b].push_back(a);
    }
    // solve
    vector<int> parent(n, -1);
    vector<int> size(n, 1);
    vector<int> depth(n);
    function<void (int)> go = [&](int i) {
        for (int j : g[i]) if (j != parent[i]) {
            parent[j] = i;
            depth[j] = depth[i] + 1;
            go(j);
            size[i] += size[j];
        }
    };
    go(0);
    int i = n - 1;
    repeat (j, (depth[n - 1] - 1) / 2) {
        i = parent[i];
    }
    int second = size[i];
    int first = n - second;
    // output
    printf("%s\n", first > second ? "Fennec" : "Snuke");
    return 0;
}
```
