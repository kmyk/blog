---
layout: post
alias: "/blog/2017/08/27/agc-019-c/"
date: "2017-08-27T02:11:25+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc", "longest-increasing-subsequence" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc019/tasks/agc019_c" ]
---

# AtCoder Grand Contest 019: C - Fountain Walk

LISって言われれば(バグらせたのを除いて)すぐだった。本番でもDをバグらさなければ解けてたのかも。

## solution

LIS。$O(N \log N)$。

サンプルから分かるように、噴水は曲がるときに通るとショートカットになり、直進するときに通るとロスとなる。
まず、$[x\_1, x\_2] \times [y\_1, y\_2]$の長方形の中を最短経路で通ればよい。
そうでない経路があったとすると、経路中に長方形の境界を伸ばした直線を踏み越えて戻ってくる部分があるが、これを境界上を一直線に進むように書き換えて経路長を減少させられる。
長方形の中で戻りが発生する場合も同様。

噴水を曲がり角に配置したいが後戻りは禁止とする。
すると使う噴水の座標は$x\_i \lt x\_{i+1} \land y\_i \lt y\_{i+1}$を満たし、LISを使ってその長さの回数$k$だけできる。
さらに基本的に横切ることは回避できる。
ただし噴水が壁のように配置されている場合は回避できない。
$w = \|x\_1 - x\_2\|$かつ$y = \|y\_1 - y\_2\|$とおいて$k = \max \\{ w, h \\} + 1$の場合がそれ。
この場合$1$度だけ横切る必要がある。

## implementation

``` c++
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define whole(x) begin(x), end(x)
using namespace std;

template <typename T>
vector<T> longest_increasing_subsequence(vector<T> const & xs) {
    vector<T> l; // l[i] is the last element of the increasing subsequence whose length is i+1
    l.push_back(xs.front());
    for (auto && x : xs) {
        auto it = lower_bound(l.begin(), l.end(), x);
        if (it == l.end()) {
            l.push_back(x);
        } else {
            *it = x;
        }
    }
    return l;
}

int main() {
    // input
    int lx, ly, rx, ry, n; scanf("%d%d%d%d%d", &lx, &ly, &rx, &ry, &n);
    int h = abs(ry - ly);
    int w = abs(rx - lx);
    vector<pair<int, int> > f;
    repeat (i, n) {
        int x, y; scanf("%d%d", &x, &y);
        x = lx <= rx ? x - lx : lx - x;
        y = ly <= ry ? y - ly : ly - y;
        if (0 <= x and x <= w and 0 <= y and y <= h) {
            f.emplace_back(x, y);
        }
    }
    // solve
    vector<int> lis;
    if (not f.empty()) {
        vector<int> g;
        sort(whole(f));
        for (auto it : f) g.push_back(it.second);
        lis = longest_increasing_subsequence(g);
    }
    double result = 100.0 * (h + w) - (20 - 5 * M_PI) * lis.size();
    if (lis.size() == min(w, h) + 1) {
        result += 5 * M_PI;
    }
    // output
    printf("%.15lf\n", result);
    return 0;
}
```
