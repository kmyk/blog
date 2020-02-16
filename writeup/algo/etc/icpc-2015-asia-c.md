---
layout: post
alias: "/blog/2015/11/30/icpc-2015-asia-c/"
date: 2015-11-30T01:24:25+09:00
tags: [ "competitive", "writeup", "icpc", "aoj", "graph", "adjacency-matrix", "game" ]
---

# ACM ICPC 2015 アジア地区予選 C : Sibling Rivalry

我々のチームは本番通せず。`A`,`B`を解いた後、私は`F`を担当して、`C`はチームメンバーに任せた。しかし`C`も`F`もバグを埋めてしまった。`C`に関して、私は終了間際まで触る余裕がなく、チームメンバーの用いていた解法すら把握していない。他人の目が入れば解決しそうな間違いだったようなので、私が`F`に手間取らなければ通っていたのでは、と思う。くやしい。

単純に問題として見ると、そこまで難しくはないと思う。

<!-- more -->

## [C : Sibling Rivalry](http://judge.u-aizu.ac.jp/onlinejudge/cdescription.jsp?cid=ICPCOOC2015&pid=C) {#c}

### 問題

有向グラフが与えられ、正整数$a,b,c$が与えられる。
あなたは相手とゲームを行う。

あなたは最初は頂点$1$にいる。1ターンにつき、以下の操作を1度行う。あなたが頂点$n$に移動すれば終了する。

1.  相手は数$a,b,c$のいずれかである数$x$を宣言する。
2.  あなたは$x$回 有向辺をたどり移動する。

あなたは頂点$n$にできるだけ短いターン数で移動することを目指す。
相手はあなたを頂点$n$に移動させないこと、あるいはできるだけ到着までのターン数を増やすことを目指す。
お互いに最適に動いたとき、あなたは頂点$n$に移動できるか、移動できるならターン数の最短はいくつか答えよ。

### 解法

相手がどのように宣言しようとも(いくつかのターンの後に)頂点$n$に到達できる頂点を、増やしていく。

頂点$n$は明らかに頂点$n$に到達できる。
もし頂点$i$から、$a,b,c$いずれの数の辺をたどっても、相手の宣言によらず頂点$n$に到達できるような頂点に到達できるとき、頂点$i$もまた相手の宣言によらず頂点$n$に到達できる頂点である。

このようにして、頂点$n$に到達できる頂点を頂点$n$のみから増やしていき、最終的に頂点$0$がそれに入るかどうかを見ればよい。
このとき、各々の頂点$n$に到達可能な頂点について、最短何ターンで到達可能かを同時に計算すれば、答えが求まる。

### 実装

-   隣接行列使うと便利と教えてもらった。
-   答えのステップ数はカウンタ変数と等しくなる。`min`や`max`は不要。

``` c++
#include <iostream>
#include <vector>
#include <set>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
int main() {
    int n, m, a, b, c; cin >> n >> m >> a >> b >> c;
    vector<vector<int> > g(n);
    repeat (i,m) {
        int u, v; cin >> u >> v;
        -- u; -- v;
        g[u].push_back(v);
    }
    vector<vector<bool> > ag, bg, cg; {
        vector<vector<bool> > x(n, vector<bool>(n)); // adjacency matrix
        repeat (i,n) {
            for (int j : g[i]) {
                x[i][j] = true;
            }
        }
        vector<vector<bool> > y = x;
        repeat (t, max(a,max(b,c))) {
            if (a == t+1) ag = y;
            if (b == t+1) bg = y;
            if (c == t+1) cg = y;
            vector<vector<bool> > z(n, vector<bool>(n));
            repeat (i,n) {
                repeat (j,n) {
                    repeat (k,n) {
                        z[i][j] = z[i][j] or (y[i][k] and x[k][j]);
                    }
                }
            }
            y = z;
        }
    }
    set<int> goals;
    goals.insert(n-1);
    for (int turn = 1; ; ++ turn) {
        vector<int> new_goals;
        repeat (i,n) if (not goals.count(i)) {
            bool ok_a = false; repeat (j,n) if (ag[i][j] and goals.count(j)) ok_a = true;
            bool ok_b = false; repeat (j,n) if (bg[i][j] and goals.count(j)) ok_b = true;
            bool ok_c = false; repeat (j,n) if (cg[i][j] and goals.count(j)) ok_c = true;
            if (ok_a and ok_b and ok_c) {
                new_goals.push_back(i);
            }
        }
        if (new_goals.empty()) {
            cout << "IMPOSSIBLE" << endl;
            break;
        }
        goals.insert(new_goals.begin(), new_goals.end());
        if (goals.count(0)) {
            cout << turn << endl;
            break;
        }
    }
    return 0;
}
```
