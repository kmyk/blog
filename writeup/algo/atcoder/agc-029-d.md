---
layout: post
date: 2018-12-16T04:34:24+09:00
tags: [ "competitive", "writeup", "atcoder", "agc", "game", "greedy" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc029/tasks/agc029_d" ]
---

# AtCoder Grand Contest 029: D - Grid game

## 解法

### 概要

パスをすると青木君にその場でゲームを終了させられてしまうために高橋君は決してパスを選べず、実質的に青木君ひとりのゲームである。
青木君が $$1 \le j \le W$$ のどこまで移動させるかをすべて考えればよく、特に、青木君も可能な場合は常に動かすとしてよい。
青木君が $$(\ast, j)$$ まで動かしたいと思ってかつ障害物によりそれが不可能な場合は存在するが、これを不可能にしている障害物を利用すれば $$(\ast, j)$$ まで動かすより早くゲームを終了させられるため気にしなくてよい。
$$O(W \log H)$$。

## メモ

-   $$1 \le X_i \le H$$ とあるように $$x, y$$ の文字が標準的なものと逆であることに注意

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
using ll = long long;
using namespace std;
template <class T, class U> inline void chmin(T & a, U const & b) { a = min<T>(a, b); }

int solve(int h, int w, int n, vector<int> const & ys, vector<int> const & xs) {
    vector<set<int> > col(w);
    REP (i, n) {
        col[xs[i]].insert(ys[i]);
    }
    REP (x, w) {
        col[x].insert(h);
    }

    int answer = INT_MAX;
    int y = 0;
    int x = 0;
    while (true) {
        chmin(answer, *col[x].upper_bound(y));
        if (col[x].count(y + 1)) {
            break;
        } else {
            ++ y;
            if (x + 1 == w) {
                // nop
            } else {
                if (not col[x + 1].count(y)) {
                    ++ x;
                }
            }
        }
    }
    return answer;
}

int main() {
    int h, w, n; cin >> h >> w >> n;
    vector<int> y(n), x(n);
    REP (i, n) {
        cin >> y[i] >> x[i];
        -- y[i];
        -- x[i];
    }
    cout << solve(h, w, n, y, x) << endl;
    return 0;
}
```
