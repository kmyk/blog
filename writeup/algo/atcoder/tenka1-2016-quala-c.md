---
layout: post
alias: "/blog/2016/07/30/tenka1-2016-quala-c/"
date: "2016-07-30T23:24:31+09:00"
tags: [ "competitive", "wirteup", "atcoder", "tenka1-programmer-contest", "graph", "directed-graph", "topological-sort" ]
"target_url": [ "https://beta.atcoder.jp/contests/tenka1-2016-quala/tasks/tenka1_2016_qualC_a" ]
---

# 天下一プログラマーコンテスト2016予選A: C - 山田山本問題

## solution

文字列間の制約のそれぞれを文字から文字への有向辺にしてtopological sort。文字の数
$l$$O(Nl^2)$。

$2$つの文字列の順序の制約は(全順序を入れるので)$2$つの文字の順序の制約と等価である。
初めて文字が異なる位置の文字だけを見ればよい。一方が一方のsuffixになっているときは自明になる。

文字の順序制約を有向グラフにする。
条件を満たす全順序の存在はこのグラフにサイクルが存在するかどうかになり、目的の順番はグラフのtopological sortであると言える。計算量の制約はゆるいので、これは適当にすれば求まる。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <array>
#include <queue>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
int main() {
    // input
    int n; cin >> n;
    vector<string> a(n), b(n); repeat (i,n) cin >> a[i] >> b[i];
    // prepare
    bool impossible = false;
    array<array<bool,26>,26> g = {}; // digraph: char -> char
    repeat (i,n) {
        int l = min(a[i].length(), b[i].length());
        int j = 0; while (j < l and a[i][j] == b[i][j]) ++ j;
        if (j == a[i].length()) {
            // nop
        } else if (j == b[i].length()) {
            impossible = true;
        } else {
            g[a[i][j]-'a'][b[i][j]-'a'] = true;
        }
    }
    string ans;
    if (not impossible) {
        array<int,26> indeg = {};
        repeat (i,26) {
            repeat (j,26) {
                if (g[i][j]) {
                    indeg[j] += 1;
                }
            }
        }
        priority_queue<int> que;
        repeat (i,26) {
            if (indeg[i] == 0) {
                que.push(- i);
            }
        }
        while (not que.empty()) {
            int i = - que.top(); que.pop();
            ans += (i + 'a');
            repeat (j,26) {
                if (g[i][j]) {
                    indeg[j] -= 1;
                    if (indeg[j] == 0) {
                        que.push(- j);
                    }
                }
            }
        }
    }
    // output
    if (ans.length() != 26) {
        ans = "-1";
    }
    cout << ans << endl;
    return 0;
}
```
