---
layout: post
date: 2018-08-22T03:30:20+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "divede-and-conquer", "branch-and-bound", "tow-pointers-technique" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc063/tasks/arc063_d" ]
redirect_from:
  - /writeup/algo/atcoder/arc-063-f/
---

# AtCoder Regular Contest 063: F - すぬけ君の塗り絵 2 / Snuke's Coloring 2

## solution

分割統治ぽい雰囲気の分枝限定法ぽい何か。計算量は分からず。

適当な点 $c = (x_c, y_c)$ を固定しよう。
白い長方形がこの点を内部に含むかどうかで場合分けをする。
含まない場合については次の$4$通り。

-   点$c$より上側の点を削除し$H' = H - y_c$として再帰
-   点$c$より下側の点を削除し$H' = y_c$として再帰
-   点$c$より左側の点を削除し$W' = W - x_c$として再帰
-   点$c$より右側の点を削除し$W' = x_c$として再帰

含む場合については$x = x_c$を軸として左右を見てしゃくとり法のようにする。
$x_c$ より左側のある点についてその位置を長方形の左端としたと仮定すると、$x_c$ より左側の点による塗り方はすべて決定される。
これにより左端$x$を決めると左側部分での下端$y_l$と上端$y_r$が定まる。
右側についても同様。
各点についてこのような下端と上端を求め、$x_c$の左右の点を上手く綴じ合わせてやれば答えが求まる。
下端と上端に関して重複排除ししゃくとり法をすればこれは $O(n)$ でできる。

しかし点 $c$ をどう決定するかが問題となる。
$x_c, y_c$をそれぞれ$N$個の点の中央値とすると$N$が毎回半分になるが、再帰する先が$4$通りあるので計算量は $T(n) = 4T(n/2) + n$ となる。
正確な値は不明だが、これは少なくとも $n \log n$ より悪い。
$x_c, y_c$を$W / 2, H / 2$とすると$W, H$のどちらかが半分になるが、同様に再帰先が$4$通りあるので計算量は落ちない。
しかし各時点で周長の上界は$2H + 2W$でありこの値は再帰のたびに小さくなる。
また問題の性質より自明な下界も$\max( 2H + 2, 2W + 2 )$として得られている。
点$c$の選び方が上のどちらであっても、この上界を使って積極的に枝刈りをすると上手くいって間に合う。

editorialでは「答えの長方形は$x = W / 2$の直線か$y = H / 2$の直線のいずれかを必ず内部に含む」ことを使っている。
この条件を満たさないものを無視することによって再帰先が$4$通りから$2$通りに減るため計算量がきちんと落ちる。

## note

editorialを見た。
あまり理解せず適当に書いたら通った。

## implementation

``` c++
#include <algorithm>
#include <cassert>
#include <iostream>
#include <tuple>
#include <vector>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < (int)(n); ++ (i))
#define REP_R(i, n) for (int i = int(n) - 1; (i) >= 0; -- (i))
#define ALL(x) begin(x), end(x)
using namespace std;
template <class T> inline void chmax(T & a, T const & b) { a = max(a, b); }
template <class T> inline void chmin(T & a, T const & b) { a = min(a, b); }

struct point_t { int y, x; };
bool operator < (point_t a, point_t b) { return a.x != b.x ? a.x < b.x : a.y < b.y; }

void solve(int h, int w, int n, vector<point_t> & p, int & perimeter) {
    if (2 * h + 2 * w <= perimeter) {
        return;
    }

    // base cases
    if (p.empty()) {
        chmax(perimeter, 2 * h + 2 * w);
        return;
    }
    if (p.size() == 1) {
        chmax(perimeter, 2 * (    p[0].y + w));
        chmax(perimeter, 2 * (h - p[0].y + w));
        chmax(perimeter, 2 * (h +     p[0].x));
        chmax(perimeter, 2 * (h + w - p[0].x));
        return;
    }
    chmax(perimeter, 2 * h + 2);
    chmax(perimeter, 2 * w + 2);

    assert (is_sorted(ALL(p)));
    const int yc = h / 2;
    const int xc = w / 2;

    // conquer
    {
        auto cmp = [&](tuple<int, int, int> a, tuple<int, int, int> b) {
            return get<1>(a) == get<1>(b) and get<2>(a) == get<2>(b);
        };

        vector<tuple<int, int, int> > left;
        {
            int ml = upper_bound(ALL(p), xc, [&](int b, point_t a) { return b < a.x; }) - p.begin();
            int yl = 0, yr = h;
            REP_R (i, ml) {
                left.emplace_back(p[i].x, yl, yr);
                if (p[i].y <= yc) chmax(yl, p[i].y);
                if (p[i].y >= yc) chmin(yr, p[i].y);
                if (p[i].y == yc) break;
            }
            if (yl < yr) left.emplace_back(0, yl, yr);
            reverse(ALL(left));
            left.erase(unique(ALL(left), cmp), left.end());
            reverse(ALL(left));
        }

        vector<tuple<int, int, int> > right;
        {
            int mr = lower_bound(ALL(p), xc, [&](point_t a, int b) { return a.x < b; }) - p.begin();
            int yl = 0, yr = h;
            REP3 (i, mr, n) {
                right.emplace_back(p[i].x, yl, yr);
                if (p[i].y <= yc) chmax(yl, p[i].y);
                if (p[i].y >= yc) chmin(yr, p[i].y);
                if (p[i].y == yc) break;
            }
            if (yl < yr) right.emplace_back(w, yl, yr);
            reverse(ALL(right));
            right.erase(unique(ALL(right), cmp), right.end());
            reverse(ALL(right));
        }

        auto get_perimeter = [&](int l, int r) {
            int lx, lyl, lyr; tie(lx, lyl, lyr) = left[l];
            int rx, ryl, ryr; tie(rx, ryl, ryr) = right[r];
            return 2 * (rx - lx) + 2 * (min(lyr, ryr) - max(lyl, ryl));
        };
        int r = 0;
        REP (l, left.size()) {
            while (r + 1 < right.size() and get_perimeter(l, r + 1) >= get_perimeter(l, r)) ++ r;
            chmax(perimeter, get_perimeter(l, r));
        }
    }

    {  // divide
        vector<point_t> upper, lower, right, left;
        REP (i, n) {
            int y = p[i].y;
            int x = p[i].x;
            if (0  < y and y < yc) lower.push_back(p[i]);
            if (yc < y and y < h ) upper.push_back((point_t) { y - yc, x });
            if (0  < x and x < xc) left .push_back(p[i]);
            if (xc < x and x < w ) right.push_back((point_t) { y, x - xc });
        }
        solve(    yc, w, lower.size(), lower, perimeter);
        solve(h - yc, w, upper.size(), upper, perimeter);
        solve(h,     xc, left .size(), left , perimeter);
        solve(h, w - xc, right.size(), right, perimeter);
    }
}

int main() {
    int w, h, n; cin >> w >> h >> n;
    vector<point_t> p(n);
    REP (i, n) cin >> p[i].x >> p[i].y;
    sort(ALL(p));
    int perimeter = 0;
    solve(h, w, n, p, perimeter);
    cout << perimeter << endl;
    return 0;
}
```
