---
layout: post
redirect_from:
  - /writeup/algo/atcoder/abc-039-d/
  - /blog/2016/06/11/abc-039-d/
date: 2016-06-11T23:00:04+09:00
tags: [ "competitive", "writeup", "atcoder", "abc" ]
"target_url": [ "https://beta.atcoder.jp/contests/abc039/tasks/abc039_d" ]
---

# AtCoder Beginner Contest 039 D - 画像処理高橋君

やるだけなわりに面倒だなと思ったままACしたが、その面倒はなんらかの勘違いに起因したものだったので敗北感がある。

## solution

元画像を直接構成する。

-   変換後画像で、周囲が全て黒なら元画像でも黒
-   そうでないなら白

こうしてできた元画像を変換して、変換後画像に一致するか見ればよい。

## implementation

不要な処理を除いたもの

``` c++
#include <iostream>
#include <vector>
#include <array>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
using namespace std;
int main() {
    int h, w; cin >> h >> w;
    auto is_on_image = [&](int y, int x) { return 0 <= y and y < h and 0 <= x and x < w; };
    auto count_neighbors = [&](vector<string> const & f, int y, int x) {
        array<int,3> cnt = {};
        repeat_from (dy,-1,1+1) {
            repeat_from (dx,-1,1+1) {
                if (not dy and not dx) continue;
                int ny = y + dy;
                int nx = x + dx;
                if (not is_on_image(ny, nx)) continue;
                if (f[ny][nx] == '.') cnt[0] += 1;
                if (f[ny][nx] == '#') cnt[1] += 1;
                if (f[ny][nx] == '?') cnt[2] += 1;
            }
        }
        return cnt;
    };
    vector<string> f(h); repeat (y,h) cin >> f[y];
    vector<string> g(h, string(w, '\0'));
    repeat (y,h) {
        repeat (x,w) {
            if (f[y][x] == '.') {
                g[y][x] = '.';
            } else if (f[y][x] == '#') {
                array<int,3> cnt = count_neighbors(f, y, x);
                g[y][x] = cnt[0] == 0 ? '#' : '.';
            }
        }
    }
    bool possible = true;
    repeat (y,h) {
        repeat (x,w) {
            array<int,3> cnt = count_neighbors(g, y, x);
            if ((cnt[1] or g[y][x] == '#') != (f[y][x] == '#')) {
                possible = false;
            }
        }
    }
    if (possible) {
        cout << "possible" << endl;
        repeat (y,h) cout << g[y] << endl;
    } else {
        cout << "impossible" << endl;
    }
    return 0;
}
```
