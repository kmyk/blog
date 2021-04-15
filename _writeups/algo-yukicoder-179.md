---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/179/
  - /blog/2016/10/08/yuki-179/
date: "2016-10-08T02:48:45+09:00"
tags: [ "competitive", "writeup", "yukicoder" ]
"target_url": [ "http://yukicoder.me/problems/no/179" ]
---

# Yukicoder No.179 塗り分け

fav数rankingの上から埋めていくのはどうかと思ってやった。このとき$2$位だった。
面白いとは思うが$2$位と言われるとそうでもない。

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) y) { return (f)(begin(y), end(y), ## __VA_ARGS__); })(x)
using namespace std;
bool is_on_field(int y, int x, int h, int w) { return 0 <= y and y < h and 0 <= x and x < w; }
int main() {
    int h, w; cin >> h >> w;
    vector<string> f(h); repeat (y,h) cin >> f[y];
    bool ans = false;
    repeat_from (dy,-h,h+1) repeat_from (dx,-w,w+1) {
        if (dy == 0 and dx == 0) continue;
        auto g = f;
        repeat (y,h) repeat (x,w) {
            if (g[y][x] == '#') {
                int ny = y + dy;
                int nx = x + dx;
                if (not is_on_field(ny, nx, h, w)) goto done;
                if (g[ny][nx] == '#') {
                    g[ny][nx] = '.';
                } else {
                    goto done;
                }
            }
        }
        ans = true;
done: ;
    }
    int area = 0; repeat (y,h) area += whole(count, f[y], '#');
    if (not area) ans = false;
    cout << (ans ? "YES" : "NO") << endl;
    return 0;
}
```
