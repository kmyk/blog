---
layout: post
redirect_from:
  - /blog/2017/12/31/arc-076-f/
date: "2017-12-31T21:19:18+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "maximum-flow" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc076/tasks/arc076_d" ]
---

# AtCoder Regular Contest 076: F - Exhausted?

自力で解けたとメモにはあったが、寝かせてから解説を書こうとしたらまったく分からなくなっていた。

## solution

最大流。愚直に流すともちろん間に合わないのでグラフの形に依存して書き直す。editorialだとsegment木だが優先度付きqueueがあれば十分。$O(N \log N)$。

各区間$[1, L\_i] \cup [R\_i, M]$について、$[1, L\_i]$側で使われた/$[R\_i, M]$側で使われた/どちらでも使われなかった、の$3$種類を割り当てるように考える。
$L\_i$でsortして左から見る。
左側で使えるなら使い、$R\_i$を「右側では使われなかったリスト」に追加。
左側で使えないなら、いったん$R\_i$を「右側では使われなかったリスト」に追加し、その中から最小値を取り出して「右側で使う予定のリスト」に追加する。
左から右へこれを舐め終わったら、「右側で使う予定のリスト」をsortして大きい順に見て貪欲に使えるだけ使う。
これで使う数が最大化される。

## implementation

``` c++
#include <algorithm>
#include <cstdio>
#include <queue>
#include <tuple>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define whole(x) begin(x), end(x)
using namespace std;
template <class T> using reversed_priority_queue = priority_queue<T, vector<T>, greater<T> >;

int main() {
    // input
    int n, m; scanf("%d%d", &n, &m);
    vector<pair<int, int> > lrs(n);
    repeat (i, n) {
        int l, r; scanf("%d%d", &l, &r); -- l; -- r;
        lrs[i] = { l, r };
    }
    // solve
    sort(whole(lrs));
    int left = 0;
    reversed_priority_queue<int> unused_rs;
    vector<int> rs;
    for (auto lr : lrs) {
        int l, r; tie(l, r) = lr;
        if (l == -1 and r == m) {
            // nop
        } else if (l == -1) {
            rs.push_back(r);
        } else {
            if (left <= l) {
                ++ left;
                unused_rs.push(r);
            } else {
                unused_rs.push(r);
                int min_r = unused_rs.top();
                unused_rs.pop();
                rs.push_back(min_r);
            }
        }
        if (left == m) {
            break;
        }
    }
    int right = m;
    sort(whole(rs));
    reverse(whole(rs));
    for (int r : rs) {
        if (left == right) {
            break;
        }
        if (r == m) {
            // nop
        } else {
            if (r < right) {
                -- right;
            }
        }
    }
    // output
    int used = left + (m - right);
    printf("%d\n", n - used);
    return 0;
}
```
