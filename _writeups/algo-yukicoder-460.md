---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/460/
  - /blog/2016/12/12/yuki-460/
date: "2016-12-12T02:03:07+09:00"
tags: [ "competitive", "writeup", "yukicoder", "dp", "bit-dp", "lights-out" ]
"target_url": [ "http://yukicoder.me/problems/no/460" ]
---

# Yukicoder No.460 裏表ちわーわ

典型lights-outだけど斜めにしないといけなくて面倒だなと思ったが、別にその必要はなかった。やられた。

## solution

$y = 0 \lor x = 0$な$H+W-1$箇所の反転の有無を決めれば残りは一意に定まる。DP。$O(2^{H+W}HW)$。

これの$4$近傍版が蟻本に載っている。

## 反省

-   問題難易度見誤った
-   `Impossible`でなく`-1`を出してWA

## implementation

``` c++
#include <iostream>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < int(n); ++(i))
typedef long long ll;
using namespace std;
template <class T> void setmin(T & a, T const & b) { if (b < a) a = b; }
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }
ll bit(int i) { return 1ll << i; }
bool is_on_field(int y, int x, int h, int w) { return 0 <= y and y < h and 0 <= x and x < w; }
const int inf = 1e9+7;
int main() {
    int h, w; cin >> h >> w;
    vector<vector<bool> > a = vectors(h, w, bool());
    repeat (y,h) repeat (x,w) {
        bool it; cin >> it;
        a[y][x] = it;
    }
    int ans = inf;
    repeat (s, bit(w)) {
        repeat (t, bit(h)) {
            int cnt = 0;
            vector<vector<bool> > b = a;
            auto flip = [&](int y, int x) {
                cnt += 1;
                repeat_from (dy,-1,1+1) repeat_from (dx,-1,1+1) {
                    int ny = y + dy;
                    int nx = x + dx;
                    if (is_on_field(ny, nx, h, w)) {
                        b[ny][nx] = not b[ny][nx];
                    }
                }
            };
            repeat (y,h) {
                repeat (x,w) {
                    if (y == 0) {
                        if (s & bit(x)) {
                            flip(y, x);
                        }
                    } else if (x == 0) {
                        if (t & bit(y-1)) {
                            flip(y, x);
                        }
                    } else {
                        if (b[y-1][x-1]) {
                            flip(y, x);
                        }
                    }
                }
            }
            bool succeeded = true;
            repeat (y,h) {
                repeat (x,w) {
                    if (b[y][x]) {
                        succeeded = false;
                    }
                }
            }
            if (succeeded) {
                setmin(ans, cnt);
            }
        }
    }
    if (ans == inf) {
        cout << "Impossible" << endl;
    } else {
        cout << ans << endl;
    }
    return 0;
}
```
