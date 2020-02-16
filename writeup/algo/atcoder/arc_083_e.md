---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc-083-e/
  - /blog/2017/10/03/arc-083-e/
date: "2017-10-03T06:01:39+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "tree", "dp", "knapsack-problem" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc083/tasks/arc083_c" ]
---

# AtCoder Regular Contest 083: E - Bichrome Tree

## solution

木DP。さらに各頂点でknapsack問題のDP。$O(NX)$。

各部分木において、その根を白に塗ったときの黒の頂点の重みの総和の最小値、その根を黒に塗ったときの白の頂点の重みの総和の最小値、をそれぞれ求めるDPをすればよい。
色を反転させれば同じになるので根は必ず白で塗ると仮定してよい。
黒の頂点の重みの総和の最小値は、子についてそれぞれ求めた後$X$が小さいことを利用してknapsack問題を解くことで求まる。

## implementation

``` c++
#include <algorithm>
#include <cstdio>
#include <functional>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define whole(x) begin(x), end(x)
using namespace std;
template <class T> inline void setmin(T & a, T const & b) { a = min(a, b); }

constexpr int inf = 1e9+7;
int main() {
    // input
    int n; scanf("%d", &n);
    vector<vector<int> > children(n);
    repeat (i, n - 1) {
        int p; scanf("%d", &p); -- p;
        children[p].push_back(i + 1);
    }
    vector<int> x(n); repeat (i, n) scanf("%d", &x[i]);

    // solve
    vector<int> dp(n);
    function<void (int)> go = [&](int i) {
        vector<int> cur(x[i] + 1, inf);
        cur[0] = 0;
        for (int j : children[i]) {
            go(j);
            vector<int> prv = move(cur);
            cur.assign(x[i] + 1, inf);
            repeat (acc, prv.size()) if (prv[acc] < inf) {
                if (acc +  x[j] <= x[i]) setmin(cur[acc +  x[j]], prv[acc] + dp[j]);
                if (acc + dp[j] <= x[i]) setmin(cur[acc + dp[j]], prv[acc] +  x[j]);
            }
        }
        dp[i] = *min_element(whole(cur));
    };
    go(0);
    bool result = dp[0] < inf;

    // output
    printf("%s\n", result ? "POSSIBLE" : "IMPOSSIBLE");
    return 0;
}
```
