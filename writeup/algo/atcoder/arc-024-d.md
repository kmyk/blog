---
layout: post
alias: "/blog/2016/03/15/arc-024-d/"
title: "AtCoder Regular Contest 024 D - バス停"
date: 2016-03-15T22:44:21+09:00
tags: [ "competitive", "writeup", "atcoder" ]
---

考えやすい感じの問題なのでちょっと好き。

## [D - バス停](https://beta.atcoder.jp/contests/arc024/tasks/arc024_4)

### 問題

二分する。軸に並行にバス停を並べ半分に分割することを繰り返す。

適当な$y = m$を固定し、全てのバス停$(x_i,y_i)$に関し、その影となる$(x_i,m)$に新たなバス停を設置する。すると直線$y = m$を間に挟むバス停同士、つまりバス停$i$と$j$が$y_i \le m \le y_j$あるいは$y_j \le m \le y_i$ならば、それらの間は最短距離で移動できる。
この分割を再帰的にやればよい。

特に、入力$N \le 1000$で、出力$M \le 10000 - N$。
$1000$から初めて再帰的に$2$で割っていくと$1000,500,250,125,62,31,15,7,3,1$となり、$9$回目で$1$になる。
設置するバス停は$1000 + (500 + 500) + (250 + 250 + 250 + 250) + \dots + (1 + 1 + \dots + 1) = 1000 \cdot 9$で抑えられるので、これで十分である。

### 実装

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <set>
#include <functional>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
using namespace std;
struct point_t { int y, x; };
bool operator == (point_t a, point_t b) { return make_pair(a.y, a.x) == make_pair(b.y, b.x); }
bool operator  < (point_t a, point_t b) { return make_pair(a.y, a.x)  < make_pair(b.y, b.x); }
const int W = 1001;
int main() {
    int n; cin >> n;
    set<point_t> ps;
    vector<set<int> > ys(W);
    repeat (i,n) {
        int y, x; cin >> x >> y;
        ps.insert((point_t) { y, x });
        ys[y].insert(x);
    }
    vector<point_t> qs;
    function<void (int, int, int)> split = [&](int l, int r, int n) {
        if (n <= 1) return;
        int acc = 0, nacc;
        int m; for (m = l; m < r; ++ m) {
            nacc = acc + ys[m].size();
            if (n/2 <= nacc) break;
            acc = nacc;
        }
        repeat_from (y, l, r) if (y != m) {
            for (int x : ys[y]) {
                qs.push_back((point_t) { m, x });
            }
        }
        split(l, m, acc);
        split(m+1, r, n - nacc);
    };
    split(0, W, n);
    qs.erase(remove_if(qs.begin(), qs.end(), [&](point_t p) { return ps.count(p); }), qs.end());
    sort(qs.begin(), qs.end());
    qs.erase(unique(qs.begin(), qs.end()), qs.end());
    cout << qs.size() << endl;
    for (point_t q : qs) cout << q.x << ' ' << q.y << endl;
    return 0;
}
```
