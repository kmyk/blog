---
layout: post
alias: "/blog/2017/05/26/arc-056-b/"
date: "2017-05-26T04:10:54+09:00"
title: "AtCoder Regular Contest 056: B - 駐車場"
tags: [ "competitive", "writeup", "atcoder", "arc", "graph" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc056/tasks/arc056_b" ]
---

以前この回に参加したときは解けず。解法が記憶に残っていたのか、今やったらすぐだった。

## solution

使える頂点を逆順に追加していく。$O(N + M)$。

$i$番目の人が駐車しようとするとき、$j \lt i$番目の駐車スペースは通行できない。それ以外は通行可能。
$i$番目の人の駐車の際にも$j \lt i$番目の駐車スペースに到達可能なら$j$番目の人が駐車していなければおかしいので矛盾、到達不可能なら通行可能性を考える必要はない。

到達可能な駐車スペースが減少していくのは面倒なので、逆から見ていく。
$S$から減らしていって$i$番目の人を考えるときは、$i+1$番目の人が到達可能だった駐車スペースに加えて$i$番目の駐車スペースも到達可能とすればよい。
$i$番目の駐車スペースに$i+1$番目の人が到達可能だった駐車スペースが隣接しているならば、$i$番目の駐車スペースから今まで到達可能でなかった$j \ge i$番目な駐車スペースのみを通って到達可能なスペースが追加で到達可能。

## implementation

``` c++
#include <cstdio>
#include <vector>
#include <algorithm>
#include <functional>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_reverse(i,n) for (int i = (n)-1; (i) >= 0; --(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using namespace std;

int main() {
    // input
    int n, m, s; scanf("%d%d%d", &n, &m, &s); -- s;
    vector<vector<int> > g(n);
    repeat (i,m) {
        int u, v; scanf("%d%d", &u, &v); -- u; -- v;
        g[v].push_back(u);
        g[u].push_back(v);
    }
    // solve
    vector<bool> reachable(n);
    reachable[s] = true;
    function<void (int, int)> go = [&](int i, int limit) {
        for (int j : g[i]) if (j >= limit and not reachable[j]) {
            reachable[j] = true;
            go(j, limit);
        }
    };
    vector<int> result;
    repeat_reverse (i,s+1) {
        bool found = false;
        if (reachable[i]) {
            found = true;
        } else {
            for (int j : g[i]) {
                if (reachable[j]) {
                    found = true;
                    break;
                }
            }
        }
        if (not found) continue;
        result.push_back(i);
        reachable[i] = true;
        go(i, i);
    }
    whole(reverse, result);
    // output
    for (int i : result) {
        printf("%d\n", i+1);
    }
    return 0;
}
```
