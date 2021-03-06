---
layout: post
redirect_from:
  - /writeup/algo/codeforces/327-d/
  - /blog/2015/12/17/cf-327-d/
date: 2015-12-17T23:54:26+09:00
tags: [ "competitive", "writeup", "codeforces" ]
"target_url": [ "!-- more --" ]
---

# Codeforces Round #191 (Div. 2) D. Block Tower

## [D. Block Tower](http://codeforces.com/contest/327/problem/D) {#d}

### 問題

$H \times W$の盤面($H, W \le 500$)が与えられる。各マスは障害物があるか空き地である。

以下の操作最大$10^6$回できる。

-   空き地に青い塔を建てる。
-   空き地で、隣接する4つのマスのいずれかに青い塔があるものに、赤い塔を建てる。
-   塔を壊して空き地に戻す。

最終的にできる盤面の状態から以下で定まる得点を最大化せよ。

-   青い塔がひとつにつき$100$点。
-   赤い塔がひとつにつき$200$点。

### 解法

空き地に関する連結成分のそれぞれについて、青い塔がひとつだけになるようにすればよい。
これは単純な深さ優先の再帰を用いて、末端から赤い塔を建てていくことで実現できる。

### 実装

-   出力の$y,x$の順がとてもが紛らわしいことに注意。サンプルとよく比較すること。
-   `cout`使ったらTLEした。

``` c++
#include <iostream>
#include <cstdio>
#include <vector>
#include <tuple>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
const int dy[] = { -1, 1, 0, 0 };
const int dx[] = { 0, 0, 1, -1 };
bool is_on(int y, int x, int h, int w) {
    return 0 <= y and y < h and 0 <= x and x < w;
}
void query(char c, int y, int x, vector<vector<char> > & s, vector<tuple<char,int,int> > & result) {
    result.emplace_back(c, y, x);
    s[y][x] = c == 'D' ? '.' : c;
}
void dfs(int y, int x, vector<vector<char> > & s, vector<tuple<char,int,int> > & result) {
    assert (s[y][x] == '.');
    int h = s.size();
    int w = s[0].size();
    bool has_blue = false;
    query('B', y, x, s, result);
    repeat (i,4) {
        int ny = y + dy[i];
        int nx = x + dx[i];
        if (not is_on(ny, nx, h, w)) continue;
        if (s[ny][nx] == '.') {
            dfs(ny, nx, s, result);
        } else if (s[ny][nx] == 'B') {
            has_blue = true;
        }
    }
    if (has_blue) {
        query('D', y, x, s, result);
        query('R', y, x, s, result);
    }
}
int main() {
    int h, w; cin >> h >> w;
    vector<vector<char> > s(h, vector<char>(w));
    repeat (y,h) repeat (x,w) cin >> s[y][x];
    vector<tuple<char,int,int> > result;
    repeat (y,h) repeat (x,w) if (s[y][x] == '.') {
        dfs(y, x, s, result);
    }
    printf("%d\n", result.size());
    for (auto it : result) printf("%c %d %d\n", get<0>(it), get<1>(it)+1, get<2>(it)+1);
    return 0;
}
```
