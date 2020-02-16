---
layout: post
alias: "/blog/2016/05/29/gcj-2016-round2-a/"
date: 2016-05-29T01:47:13+09:00
tags: [ "competitive", "writeup", "gcj", "google-code-jam" ]
"target_url": [ "https://code.google.com/codejam/contest/10224486/dashboard#s=p0" ]
---

# Google Code Jam 2016 Round 2 A. Rather Perplexing Showdown

誤読した。
全体としては、Tシャツは貰えなかった。(ボーダーを誤認していたために解く順番を間違えた)

## problem

$2^N$人の人間がいて、トーナメント式のじゃんけん大会をする。
それぞれの人間は全ての対戦で同じ手を出し続ける。
グー チョキ パーの手を出し続ける人間がそれぞれ$G, P, S$人いる。
あいこによる無限ループが発生しないようなトーナメントの組み方を答えよ。
特に、*辞書順最小*のものを答えよ。

## solution

The tournament-trees are uniquely determined by the $n$ and the root hand $h \in \\{ 'G', 'P', 'S' \\}. $O(N^2)$.

If the root is `R`, then the two roots of the subtrees have to be `R` and `S`.
Such restriction determines the rooted-trees for each pair $(n, h)$,  uniquely up to the isomorphism.
So you can prepare all of the required rooted-trees.
Then, to match the trees and the input is enough.

## implementation

``` c++
#include <iostream>
#include <vector>
#include <array>
#include <algorithm>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;

#define MAX_N 12
array<array<string,3>,MAX_N+1> memo;
void init() {
    memo[0][0] = "R";
    memo[0][1] = "P";
    memo[0][2] = "S";
    repeat (i,MAX_N) {
        repeat (j,3) {
            string const & s = memo[i][(j+0)%3];
            string const & t = memo[i][(j+2)%3];
            memo[i+1][j] = min(s + t, t + s);
        }
    }
}
void solve() {
    int n, r, p, s; cin >> n >> r >> p >> s;
    repeat (i,3) {
        string const & t = memo[n][i];
        if (r != count(t.begin(), t.end(), 'R')) continue;
        if (p != count(t.begin(), t.end(), 'P')) continue;
        if (s != count(t.begin(), t.end(), 'S')) continue;
        cout << t << endl;
        return;
    }
    cout << "IMPOSSIBLE" << endl;
}
int main() {
    init();
    int t; cin >> t;
    repeat (i,t) {
        cout << "Case #" << i+1 << ": ";
        solve();
    }
    return 0;
}
```
