---
layout: post
alias: "/blog/2016/11/30/code-festival-2016-relay-k/"
date: "2016-11-30T01:33:37+09:00"
tags: [ "competitive", "writeup", "atcoder", "codefestival", "tree", "dp" ]
"target_url": [ "https://beta.atcoder.jp/contests/cf16-relay-open/tasks/relay_k" ]
---

# CODE FESTIVAL 2016 Relay: K - 木の問題 / Problem on Tree

darinflarさんとsigmaさんにほぼ任せていた。木DPであり話を聞く限り通りそうだったがWAが出て通らず。
後から解きなおして(WAを出して)気付いたが本番での自分の理解には抜けがあって、親方向の葉を見るのを忘れていた。

## solution

木DP。各部分木ごとに、その部分木を経由する場合の$v$に含められる頂点の数(つまり葉の数)と、その部分木中の頂点を$v$の端点として用いた場合の$v$に含められる頂点の数を求める。$O(N)$。

答えとなる値の出し方には注意が必要である。
各頂点について、その頂点を使うとした場合はその子の中で(親方向は親が考えてくれるので無視してよい)端点として使ったときに大きい部分木を$2$つ選んで足せばよい。
一方その頂点を使わないとした場合は問題で、端点は両方その部分木から選ぶ(そうしたときの差分が大きい$2$つを選ぶ)としてよいが、親方向にある葉も使ってよいのでこれを足さねばならない。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <functional>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
template <class T> void setmax(T & a, T const & b) { if (a < b) a = b; }
int main() {
    // input
    int n; cin >> n;
    vector<vector<int> > g(n);
    repeat (i,n-1) {
        int p, q; cin >> p >> q; -- p; -- q;
        g[p].push_back(q);
        g[q].push_back(p);
    }
    // compute
    int total_leaves = 0;
    repeat (i,n) if (g[i].size() == 1) total_leaves += 1;
    int ans = 0;
    vector<int> middle(n), terminal(n); // dp on tree
    function<void (int, int)> go = [&](int i, int parent) {
        // prepare
        int sum_middle = 0;
        vector<int> terminals;
        vector<int> diff;
        for (int j : g[i]) if (j != parent) {
            go(j, i);
            sum_middle += middle[j];
            terminals.push_back(terminal[j]);
            diff.push_back(terminal[j] - middle[j]);
        }
        diff.push_back(0);
        diff.push_back(0);
        sort(diff.rbegin(), diff.rend());
        terminals.push_back(0);
        terminals.push_back(0);
        sort(terminals.rbegin(), terminals.rend());
        // result
        middle[i] = max(1, sum_middle);
        terminal[i] = max(1 + terminals[0], sum_middle + diff[0]);
        setmax(ans, 1 + terminals[0] + terminals[1]);
        setmax(ans, total_leaves + diff[0] + diff[1]);
    };
    go(0, -1);
    // output
    cout << ans << endl;
    return 0;
}
```
