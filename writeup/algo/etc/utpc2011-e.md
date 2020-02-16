---
layout: post
alias: "/blog/2017/12/25/utpc2011-e/"
date: "2017-12-25T19:10:47+09:00"
tags: [ "competitive", "writeup", "utpc", "atcoder", "aoj", "scheduling", "greedy" ]
---

# 東京大学プログラミングコンテスト2011: E. ファーストアクセプタンス

-   <http://www.utpc.jp/2011/problems/first_ac.html>
-   <https://beta.atcoder.jp/contests/utpc2011/tasks/utpc2011_5>
-   <http://judge.u-aizu.ac.jp/onlinejudge/description.jsp?id=2263>

正直なところDPすら思い付かなかった。なぜなのか

## solution

次のようなスケジューリング問題として言い換えられる: 仕事$i$は実行に$A\_i$時間かかって期限は$B\_i$、処理する仕事の個数を最大化せよ。
期限の早い順に見る。
$i$個目まで見て$j$個処理するのにかかる最小の時間を$\mathrm{dp}(i, j)$とする$O(N^2)$が可能。
これを優先度付きqueueで加速すれば$O(N \log N)$。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define ALL(x) begin(x), end(x)
using namespace std;

int main() {
    // input
    int n; scanf("%d", &n);
    vector<int> a(n), b(n);
    REP (i, n) scanf("%d%d", &a[i], &b[i]);
    // solve
    vector<int> order(n);
    iota(ALL(order), 0);
    sort(ALL(order), [&](int i, int j) { return b[i] < b[j]; });
    priority_queue<int> que;
    int sum_que = 0;
    for (int i : order) {
        sum_que += a[i];
        que.push(a[i]);
        if (sum_que > b[i]) {
            sum_que -= que.top();
            que.pop();
        }
    }
    // output
    printf("%d\n", int(que.size()));
    return 0;
}
```
