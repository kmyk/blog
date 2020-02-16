---
layout: post
redirect_from:
  - /writeup/algo/atcoder/abc-037-d/
  - /blog/2016/05/14/abc-037-d/
date: 2016-05-14T20:01:12+09:00
tags: [ "competitive", "writeup", "atcoder", "abc" ]
"target_url": [ "https://beta.atcoder.jp/contests/abc037/tasks/abc037_d" ]
---

# AtCoder Beginner Contest 037 D - 経路

atcoderで`cin`を殺してくるの珍しい。油断してTLEした。

## solution

なんらかの愚直な計算をすればよい。$O(HW)$。
実装は以下のいづれか。

-   左上から右下へ順に、メモ化再帰
-   値の大きいものからソートして順に、DP

## implementation

入力の量が大きい。`scanf`/`printf`を使う。

clang + `cin`/`cout`だとTLEする。gccだと大丈夫。10倍ぐらいの速度差があったとのことである。

``` c++
#include <cstdio>
#include <vector>
#include <algorithm>
#include <tuple>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
const int dy[] = { -1, 1, 0, 0 };
const int dx[] = { 0, 0, 1, -1 };
const int mod = 1e9+7;
int main() {
    int h, w; scanf("%d%d", &h, &w);
    vector<vector<int> > a(h, vector<int>(w));
    vector<tuple<int,int,int> > q;
    repeat (y,h) repeat (x,w) {
        scanf("%d", &a[y][x]);
        q.push_back(make_tuple(a[y][x], y, x));
    }
    sort(q.rbegin(), q.rend());
    int ans = 0;
    vector<vector<int> > dp(h, vector<int>(w, 1));
    for (auto it : q) {
        int ayx, y, x; tie(ayx, y, x) = it;
        repeat (i,4) {
            int ny = y + dy[i];
            int nx = x + dx[i];
            if (0 <= ny and ny < h and 0 <= nx and nx < w) {
                if (ayx < a[ny][nx]) {
                    dp[y][x] = (dp[y][x] + dp[ny][nx]) % mod;
                }
            }
        }
        ans = (ans + dp[y][x]) % mod;
    }
    printf("%d\n", ans);
    return 0;
}
```
