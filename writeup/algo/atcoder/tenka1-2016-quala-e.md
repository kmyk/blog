---
layout: post
date: 2018-07-09T04:05:53+09:00
tags: [ "competitive", "writeup", "atcoder", "tenka1", "graph", "infinite-graph" ]
"target_url": [ "https://beta.atcoder.jp/contests/tenka1-2016-quala/tasks/tenka1_2016_qualA_e" ]
---

# 天下一プログラマーコンテスト2016予選A: E - 無限グラフ

## note

体感$700$点。
昔に本番中に見たときはさっぱりだったが、今見ると流れでやるだけだった。
なお過去の私はそもそもほぼ書くだけのDも解けてなかったぽい。

## solution

落ち着いて丁寧にやってください系のICPCな問題。$O(N + M)$。
[editorial](https://tenka1-2016-quala.contest.atcoder.jp/data/other/tenka1-2016-quala/editorial.pdf)だと綺麗な定式化をしてるが、ACだけなら雰囲気で十分。

考察1:
次のように幅$N$の表を書いて縦列ごとにまとめる。
$N$頂点$0, 1, 2, \dots, N - 1$の間に$E = \\{ (A_i, B_i) \mid 1 \le i \le M \\}$で辺を貼ったグラフ$F$の連結成分ごとに考えればよい。

<div>$$\begin{matrix}
    \vdots & \vdots & \vdots & & \vdots \\
    0 & 1 & 2 & \dots & N - 1 \\
    N & N + 1 & N + 2 & \dots & 2N - 1 \\
    2N & 2N + 1 & 2N + 2 & \dots & 3N - 1 \\
    3N & 3N + 1 & 3N + 2 & \dots & 4N - 1 \\
    \vdots & \vdots & \vdots & & \vdots
\end{matrix}$$</div>

考察2:
グラフ$F$の連結成分はひとつと仮定してよい。
元のグラフ$G$が無限個の連結成分を含むかの判定だけ考えよう。
これはグラフ$F$が一直線状であるかどうかと同じ。

考察3:
さらにグラフ$F$は一直線状ではないと仮定してよい。
グラフ$G$の連結成分は有限だが、具体的な個数を知りたい。
幅$N$の表で考えたとき、仮定より、同じ連結成分中の異なるの$2$点で同じ縦列に含まれるようなものが存在する。
そのような対は周期性を生む。よってすべての対の間隔についてその最大公約数を取れば、それが連結成分の個数。


## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
using namespace std;
template <typename T> T gcd(T a, T b) { while (a) { b %= a; swap(a, b); } return b; }

int main() {
    // input
    int n; cin >> n;
    int m; cin >> m;
    vector<vector<int> > fwd(n);
    vector<vector<int> > bck(n);
    REP (i, m) {
        int a, b; cin >> a >> b;
        fwd[a].push_back(b);
        bck[b].push_back(a);
    }

    // solve
    vector<int> used(n, INT_MAX);
    int cycle;
    function<void (int, int)> go = [&](int a, int k) {
        if (used[a] != INT_MAX) {
            int c = abs(used[a] - k);
            if (c != 0) {
                if (cycle == INT_MAX) {
                    cycle = c;
                } else {
                    cycle = gcd(cycle, c);
                }
            }
        } else {
            used[a] = k;
            for (int b : fwd[a]) {
                go(b, k + 1);
            }
            for (int z : bck[a]) {
                go(z, k - 1);
            }
        }
    };
    int answer = 0;
    REP (a, n) if (used[a] == INT_MAX) {
        cycle = INT_MAX;
        go(a, 0);
        if (cycle == INT_MAX) {
            answer = -1;
            break;
        } else {
            answer += cycle;
        }
    }

    // output
    cout << answer << endl;
    return 0;
}
```
