---
layout: post
redirect_from:
  - /writeup/algo/atcoder/jag2017summer-day3-e/
  - /blog/2017/10/03/jag2017summer-day3-e/
date: "2017-10-03T06:58:41+09:00"
tags: [ "competitive", "writeup", "atcoder", "jag-summer", "dp", "graph" ]
"target_url": [ "https://beta.atcoder.jp/contests/jag2017summer-day3/tasks/jag2017summer_day3_e" ]
---

# Japan Alumni Group Summer Camp 2017 Day 3: E - Route Calculator

チームメンバーに任せた(私のlaptopの電源が切れたので)が、バグったので私が$0$から書き直した。
私$\to$彼と私$\gets$彼のどちらの向きでも、大きめのコードをバグらせたら交代して$0$からが良いと踏んでいるがどうなのだろうか。

## problem

下図のような文字列が与えられる。左上から右下への経路で、それを数式として読んだとき最大になるようなものの値を答えよ。

```
8+9*4*8
*5*2+3+
1*3*2*2
*5*1+9+
1+2*2*2
*3*6*2*
7*7+6*5
*5+7*2+
3+3*6+8
```

## solution

`*`, `+`を辺と見てそれぞれだけでグラフ$G\_\times, G\_+$を作る。
この上でDP。
頂点$(y, x)$から$G\_\times$の辺を任意回使って到達可能な頂点から$G\_+$の辺をちょうど$1$本使っていける頂点の値を見ていい感じにする。
右下まで直接行ける場合は例外。
$O(H^2W^2)$。

## implementation

``` c++
#include <cctype>
#include <cmath>
#include <cstdio>
#include <queue>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_reverse(i, n) for (int i = (n)-1; (i) >= 0; --(i))
using ll = long long;
using namespace std;
template <class T> inline void setmax(T & a, T const & b) { a = max(a, b); }

int main() {
    // input
    int h, w; scanf("%d%d", &h, &w);
    vector<char> f(h * w);
    repeat (y, h) repeat (x, w) {
        scanf(" %c", &f[y * w + x]);
    }

    // solve
    // // make graphs
    vector<vector<int> > mul(h * w);
    vector<vector<int> > add(h * w);
    repeat (y, h) repeat (x, w) if (isdigit(f[y * w + x])) {
        int z = y * w + x;
        if (y + 1 < h) {
            auto & g = (f[(y + 1) * w + x] == '*' ? mul : add);
            if (y + 2 < h) g[z].push_back((y + 2) * w + x);
            if (x + 1 < w) g[z].push_back((y + 1) * w + (x + 1));
        }
        if (x + 1 < w) {
            auto & g = (f[y * w + (x + 1)] == '*' ? mul : add);
            if (x + 2 < w) g[z].push_back(y * w + (x + 2));
            if (y + 1 < h) g[z].push_back((y + 1) * w + (x + 1));
        }
    }
    // // dp
    vector<double> dp(h * w);
    vector<double> muls(h * w);
    queue<int> que;
    repeat_reverse (y, h) repeat_reverse (x, w) if (isdigit(f[y * w + x])) {
        int z = y * w + x;
        muls.assign(h * w, - INFINITY);
        muls[z] = f[z] - '0';
        que.push(z);
        while (not que.empty()) {
            int z = que.front();  // shadowing
            que.pop();
            for (int nz : mul[z]) {
                if (isinf(muls[nz])) {
                    que.push(nz);
                }
                setmax(muls[nz], muls[z] * (f[nz] - '0'));
            }
        }
        repeat (nz, h * w) if (not isinf(muls[nz])) {
            for (int nnz : add[nz]) {
                setmax(dp[z], muls[nz] + dp[nnz]);
            }
        }
        setmax(dp[z], muls[h * w - 1]);
    }

    // output
    if (dp[0] <= 1e16 and ll(dp[0]) <= 1000000000000000ll) {
        printf("%lld\n", ll(dp[0]));
    } else {
        printf("-1\n");
    }
    return 0;
}
```
