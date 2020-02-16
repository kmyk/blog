---
layout: post
alias: "/blog/2017/09/02/agc-009-b/"
date: "2017-09-02T08:27:46+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc", "graph", "tree", "dp" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc009/tasks/agc009_b" ]
---

# AtCoder Grand Contest 009: B - Tournament

## solution

木DP。$O(N \log N)$。

数値$a\_i$は人$i, a\_i$が戦って$a\_i$が勝ったことを示す。
つまりトーナメント中に次のような部分が存在する。

```
       a_i
        |
     .--+--.
     |     |
    a_i    i
```

優勝者は決まっているので、それぞれの人がどの順番で相手を倒したかしか自由度はない。
例えば$a\_i = a\_j = a$なら、次の図の`*`に`i`か`j`を配置する$2$通り。

```
           a
           |
        .--+--.
        |     |
        a     *
        |
     .--+--.
     |     |
     a     *
```

部分木の高さは低くて損しないので、木DPで下から決めていけばよい。

## implementation

``` c++
#include <algorithm>
#include <cstdio>
#include <functional>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define whole(x) begin(x), end(x)
using namespace std;

int main() {
    int n; scanf("%d", &n);
    vector<vector<int> > g(n);
    repeat (i, n - 1) {
        int a_i_1; scanf("%d", &a_i_1); -- a_i_1;
        g[a_i_1].push_back(i + 1);
    }
    vector<int> dp(n);
    function<void (int)> go = [&](int i) {
        if (g[i].empty()) return;
        vector<int> acc;
        for (int j : g[i]) {
            go(j);
            acc.push_back(dp[j]);
        }
        sort(whole(acc));
        reverse(whole(acc));
        repeat (k, acc.size()) acc[k] += k + 1;
        dp[i] = *max_element(whole(acc));
    };
    go(0);
    printf("%d\n", dp[0]);
    return 0;
}
```
