---
layout: post
alias: "/blog/2016/04/24/jag2016-domestic-f/"
date: 2016-04-24T23:58:53+09:00
tags: [ "competitive", "writeup", "atcoder", "jag", "icpc" ]
"target_url": [ "https://beta.atcoder.jp/contests/jag2016-domestic/tasks/jag2016secretspring_f" ]
---

# JAG Contest 2016 Domestic F - 土地相続

本番中に解法は分かっていたが、E問題を優先したため実装する時間はなかった。

## solution

分割する。$O((W + H)^N)$程度だろう。

タイル型ウィンドウマネージャやvimやemacsのウィンドウの分割のように、領域を分割していく。
すると、$N-1$回分割し、$1$回ごとに分割方法の選択肢は$W + H$個、二分木になることを考慮しても間に合う。

ただしこれだけでは、使われない領域が発生する場合を漏らしている。
$N \le 4$なので、そのようなケースは以下のようなもの(`.`で示した領域が使われない場合)であり、(鏡像を除いて)これのみである。

```
AAAAAABBB
AAAAAABBB
DD....BBB
DD....BBB
DDCCCCCCC
DDCCCCCCC
DDCCCCCCC
```


## implementation

``` c++
#include <iostream>
#include <vector>
#include <map>
#include <tuple>
#include <functional>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
template <class T> bool setmax(T & l, T const & r) { if (not (l < r)) return false; l = r; return true; }
using namespace std;
template <typename T>
T mins(T x) { return x; }
template <typename T, typename... Ts>
T mins(T x, T y, Ts... zs) { return min(x, mins(y, zs...)); }
int main() {
    int h, w, n; cin >> h >> w >> n;
    vector<vector<int> > a(h, vector<int>(w)); repeat (y,h) repeat (x,w) cin >> a[y][x];
    assert (2 <= n and n <= 4);
    vector<vector<int> > acc(h+1, vector<int>(w+1));
    repeat (y,h) repeat (x,w) acc[y+1][x+1] = acc[y+1][x] + a[y][x];
    repeat (x,w) repeat (y,h) acc[y+1][x+1] += acc[y][x+1];
    auto sum = [&](int ly, int lx, int ry, int rx) {
        return acc[ry][rx] - acc[ry][lx] - acc[ly][rx] + acc[ly][lx];
    };
    int ans = 0;
    if (n == 4) {
        repeat (ry,h+1) {
            repeat (ly,ry) {
                repeat (rx,w+1) {
                    repeat (lx,rx) {
                        setmax(ans, mins(
                                sum( 0,  0, ly, rx),
                                sum( 0, rx, ry,  w),
                                sum(ry, lx,  h,  w),
                                sum(ly,  0,  h, lx)));
                        setmax(ans, mins(
                                sum( 0,  0, ry, lx),
                                sum( 0, lx, ly,  w),
                                sum(ly, rx,  h,  w),
                                sum(ry,  0,  h, rx)));
                    }
                }
            }
        }
    }
    map<tuple<int,int,int,int,int>,int> memo;
    function<int (int, int, int, int, int)> rec = [&](int ly, int lx, int ry, int rx, int n) {
        if (n == 1) return sum(ly, lx, ry, rx);
        auto key = make_tuple(ly, lx, ry, rx, n);
        if (memo.count(key)) return memo[key];
        int ans = -1;
        repeat_from (an,1,n) {
            int bn = n - an;
            repeat_from (my,ly+1,ry) {
                int a = rec(ly, lx, my, rx, an);
                int b = rec(my, lx, ry, rx, bn);
                setmax(ans, min(a, b));
            }
            repeat_from (mx,lx+1,rx) {
                int a = rec(ly, lx, ry, mx, an);
                int b = rec(ly, mx, ry, rx, bn);
                setmax(ans, min(a, b));
            }
        }
        return memo[key] = ans;
    };
    setmax(ans, rec(0, 0, h, w, n));
    cout << ans << endl;
    return 0;
}
```
