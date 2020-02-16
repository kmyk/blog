---
layout: post
date: 2018-09-14T02:28:36+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "geometry", "convex-hull", "lie", "postscript" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc022/tasks/arc022_4" ]
redirect_from:
  - /writeup/algo/atcoder/arc-022-d/
---

# AtCoder Regular Contest 022: D - スプリンクラー

## 解法

editorialとほぼ同様。
実装の簡略化のため誤魔化しを入れたので計算量は曖昧。

与えられた点群の凸包を取り、それを順に見ながら外周の点を列挙していく。
特に$x$軸に平行な直線$y = k \in \mathbb{Z}$との交点を列挙し、その後$y$の値ごとにimos法をする。
外周の点の列挙は気合でやるしかないが、特に難しいのは「円と円の交点が格子点上に乗る場合」「複数の円の対が同じ交点を持つ場合」「このふたつが同時に起こる場合」である。
しかしそのような場合は高々数個しか出現しないので、imos法の過程で重複度を良く見て、壊れていそうならその行だけ愚直解に切り替えるようにすると上手く誤魔化せる。

## メモ

-   記述時現在、私を含めてまだ4人しか通してないらしい。でもそこまでやばいやつではなかった
-   PostScriptでvisualizerを書くのすごくよかった

<blockquote class="twitter-tweet" data-lang="ja"><p lang="ja" dir="ltr">PostScriptは幾何問のdebugに便利 <a href="https://t.co/ndyZVa930m">pic.twitter.com/ndyZVa930m</a></p>&mdash; うさぎ (@a3VtYQo) <a href="https://twitter.com/a3VtYQo/status/1039649495359746049?ref_src=twsrc%5Etfw">2018年9月11日</a></blockquote>
<script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

## 実装

### visualizer

``` python
#!/usr/bin/env python3
import math

# input
n = int(input())
xs, ys = [], []
for _ in range(n):
    x, y = map(int, input().split())
    xs += [ x ]
    ys += [ y ]

# get the bounding box
lx, ly = 0, 0
rx, ry = 0, 0
for x, y in zip(xs, ys):
    r = math.ceil(math.sqrt(x ** 2 + y ** 2))
    lx = min(lx, x - r)
    ly = min(ly, y - r)
    rx = max(rx, x + r)
    ry = max(ry, y + r)
lx -= 3
ly -= 3
rx += 3
ry += 3

# header
scale = 30
dot = 3
print('%!PS-Adobe-3.0 EPSF-3.0')
print('%%BoundingBox:', *map(lambda z: int(z * scale), [ lx + 0.5, ly + 0.5, rx - 0.5, ry - 0.5]))

# background
print(1, 1, 1, 'setrgbcolor')  # white
print('newpath')
print(lx * scale, ly * scale, 'moveto')
print(lx * scale, ry * scale, 'lineto')
print(rx * scale, ry * scale, 'lineto')
print(rx * scale, ly * scale, 'lineto')
print(lx * scale, ly * scale, 'lineto')
print('fill')

# grid
print(0, 0, 0, 'setrgbcolor')  # black
for y in range(ly, ry + 1):
    print('newpath')
    print(lx * scale, y * scale, 'moveto')
    print(rx * scale, y * scale, 'lineto')
    print('stroke')

# grid
print(0, 0, 0, 'setrgbcolor')  # black
for x in range(lx, rx + 1):
    print('newpath')
    print(x * scale, ly * scale, 'moveto')
    print(x * scale, ry * scale, 'lineto')
    print('stroke')

# circles
print(0, 0, 1, 'setrgbcolor')  # blue
for x, y in zip(xs, ys):
    r = math.sqrt(x ** 2 + y ** 2)
    print('newpath')
    print(x * scale, y * scale, r * scale, 0, 360, 'arc')  # circle
    print('stroke')

# points
print(0, 0.8, 0, 'setrgbcolor')  # green
for y in range(ly, ry + 1):
    for x in range(lx, rx + 1):
        for x1, y1 in zip(xs, ys):
            if (x - x1) ** 2 + (y - y1) ** 2 <= x1 ** 2 + y1 ** 2:
                print('newpath')
                print(x * scale, y * scale, dot, 0, 360, 'arc')  # circle
                print('fill')
                break

# origin
print(0.9, 0, 0, 'setrgbcolor')  # red
print('newpath')
print(0 * scale, 0 * scale, dot, 0, 360, 'arc')  # circle
print('fill')

# footer
print('%%EOF')
```

### 本体

``` c++
#include <algorithm>
#include <cassert>
#include <cmath>
#include <iostream>
#include <tuple>
#include <vector>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < (int)(n); ++ (i))
#define ALL(x) begin(x), end(x)
using ll = long long;
using namespace std;

ll sq(ll x) { return x * x; }

struct point_t { int y, x; };
ll dot(point_t a, point_t b) { return (ll)a.x * b.x + (ll)a.y * b.y; }
ll cross(point_t a, point_t b) { return (ll)a.x * b.y - (ll)a.y * b.x; }
ll sqabs(point_t a) { return dot(a, a); }
double abs(point_t a) { return sqrt(sqabs(a)); }

int ccw(point_t a, point_t b, point_t c) {
    b.y -= a.y;
    b.x -= a.x;
    c.y -= a.y;
    c.x -= a.x;
    if (cross(b, c) > 0) return +1;  // counter clockwise
    if (cross(b, c) < 0) return -1;  // clockwise
    if (dot(b, c) < 0)   return +2;  // c--a--b on line
    if (sqabs(b) < sqabs(c)) return -2;  // a--b--c on line
    return 0;
}

vector<point_t> convex_hull(vector<point_t> ps) {
    int n = ps.size();
    if (n <= 2) return ps;
    int k = 0;
    sort(ps.begin(), ps.end(), [&](point_t const a, point_t const b) { return make_pair(a.x, a.y) < make_pair(b.x, b.y); });
    vector<point_t> ch(2 * n);
    for (int i = 0; i < n; ch[k ++] = ps[i ++]) {  // lower-hull
        while (k >= 2 and ccw(ch[k - 2], ch[k - 1], ps[i]) <= 0) -- k;
    }
    for (int i = n - 2, t = k + 1; i >= 0; ch[k ++] = ps[i --]) {  // upper-hull
        while (k >= t and ccw(ch[k - 2], ch[k - 1], ps[i]) <= 0) -- k;
    }
    ch.resize(k - 1);
    return ch;
}

constexpr double eps = 1e-8;
constexpr int size = 300000;

pair<double, double> get_cross_points(point_t p, point_t q) {
    // let ax + by + c = 0 be the line through p and q
    ll a = q.y - p.y;
    ll b = p.x - q.x;
    ll c = - p.x * a - p.y * b;
    assert (a * p.x + b * p.y + c == 0);
    assert (a * q.x + b * q.y + c == 0);
    assert (a != 0 or b != 0);
    // bx - ay = 0 is the perpendicular
    double x = - a * c / (pow(a, 2) + pow(b, 2));
    double y = - b * c / (pow(a, 2) + pow(b, 2));
    x *= 2;
    y *= 2;
    // assert (abs(pow(y - p.y, 2) + pow(x - p.x, 2) - (sq(p.y) + sq(p.x))) < eps);  // fails when eps is enough small to get AC
    // assert (abs(pow(y - q.y, 2) + pow(x - q.x, 2) - (sq(q.y) + sq(q.x))) < eps);
    return make_pair(y, x);
}

pair<int, int> get_xl_xr(point_t p, int y) {
    // solve x^2 + bx + c = 0
    int b = - 2 * p.x;
    ll c = sq(p.x) + sq(y - p.y) - sqabs(p);
    assert (sq(b) - 4 * c >= 0);
    int x0 = - b / 2;
    double dx = sqrt(sq(b) - 4 * c) / 2.0;
    int xl = ceil(x0 - dx - eps);
    int xr = ceil(x0 + dx + eps);
    return make_pair(xl, xr);
}

pair<int, int> get_yl_yr(point_t p) {
    double r = abs(p);
    int yl = ceil(p.y - r - eps);
    int yr = ceil(p.y + r + eps);
    assert (- size <= yl and yl <= yr and yr <= size);
    return make_pair(yl, yr);
}

int solve_for_y(int n, vector<point_t> const & ps, int y) {
    int cnt = 0;
    vector<pair<int, char> > imos;
    for (auto p : ps) {
        int yl, yr; tie(yl, yr) = get_yl_yr(p);
        if (y < yl or yr <= y) continue;
        int xl, xr; tie(xl, xr) = get_xl_xr(p, y);
        imos.emplace_back(xl, +1);
        imos.emplace_back(xr, -1);
    }
    sort(ALL(imos));
    int last = - size;
    int acc = 0;
    for (auto it : imos) {
        if (acc) cnt += it.first - last;
        last = it.first;
        acc += it.second;
    }
    return cnt;
}

ll solve(int n, vector<point_t> ps) {
    ps = convex_hull(ps);
    n = ps.size();

    vector<tuple<int, int, int> > imos;
    double last_y1 = INFINITY;
    double last_x1 = INFINITY;
    REP (i, n) {
        point_t p = ps[i];

        // points
        int j1 = (i - 1 + n) % n;
        int j2 = (i + 1) % n;
        double y1, x1;
        double y2, x2;
        if (n <= 2) {
            y1 = x1 = 0.0;
            y2 = x2 = 0.0;
        } else {
            tie(y1, x1) = get_cross_points(p, ps[j1]);
            tie(y2, x2) = get_cross_points(p, ps[j2]);
        }

        // angles
        double a1 = atan2(y1 - p.y, x1 - p.x);
        double a2 = atan2(y2 - p.y, x2 - p.x);
        assert (- M_PI < a1 + eps and a1 < M_PI + eps);
        assert (- M_PI < a2 + eps and a2 < M_PI + eps);

        // some circles has the same point as (x1, y1)
        if (abs(y1 - last_y1) < eps and abs(x1 - last_x1) < eps) {
            a1 += eps;
        }
        last_y1 = y1;
        last_x1 = x1;

        bool plus_pi_2 =
            (a1 < M_PI_2 + eps and M_PI_2 < a2 + eps)
            or (a2 < a1 and a1 < M_PI_2 + eps)
            or (M_PI_2 < a2 + eps and a2 < a1);
        bool minus_pi_2 =
            (a1 < - M_PI_2 + eps and - M_PI_2 < a2 + eps)
            or (a2 < a1 and a1 < - M_PI_2 + eps)
            or (- M_PI_2 < a2 + eps and a2 < a1);
        bool start_right = (- M_PI_2 < a1 + eps and a1 <   M_PI_2 + eps);
        bool start_left  = (  M_PI_2 < a1 + eps or  a1 < - M_PI_2 + eps);
        bool end_right   = (- M_PI_2 < a2 + eps and a2 <   M_PI_2 + eps);
        bool end_left    = (  M_PI_2 < a2 + eps or  a2 < - M_PI_2 + eps);

        { // the left half
            vector<pair<int, int> > ranges;
            if (n <= 2) {
                int yl, yr; tie(yl, yr) = get_yl_yr(p);
                ranges.emplace_back(yl, yr);
            } else if (start_right and plus_pi_2 and minus_pi_2) {
                int yl, yr; tie(yl, yr) = get_yl_yr(p);
                ranges.emplace_back(yl, yr);
            } else if (start_left and not minus_pi_2) {  // contained in it
                int yl = ceil(y2 - eps);
                int yr = ceil(y1 - eps);
                ranges.emplace_back(yl, yr);
            } else {
                if (start_left and minus_pi_2) {  // starts in it and go to the right half
                    int yl = get_yl_yr(p).first;
                    int yr = ceil(y1 - eps);
                    ranges.emplace_back(yl, yr);
                }
                if (plus_pi_2 and end_left) {  // come from the right half and ends in it
                    int yl = ceil(y2 - eps);
                    int yr = get_yl_yr(p).second;
                    ranges.emplace_back(yl, yr);
                }
            }
            for (auto range : ranges) {
                int yl, yr; tie(yl, yr) = range;
                REP3 (y, yl, yr) {
                    int xl = get_xl_xr(p, y).first;
                    imos.emplace_back(y, xl, +1);
                }
            }
        }

        { // the right half
            vector<pair<int, int> > ranges;
            if (n <= 2) {
                int yl, yr; tie(yl, yr) = get_yl_yr(p);
                ranges.emplace_back(yl, yr);
            } else if (start_left and minus_pi_2 and plus_pi_2) {  // use all of it
                int yl, yr; tie(yl, yr) = get_yl_yr(p);
                ranges.emplace_back(yl, yr);
            } else if (start_right and not plus_pi_2) {  // containd in it
                int yl = ceil(y1 - eps);
                int yr = ceil(y2 - eps);
                ranges.emplace_back(yl, yr);
            } else {
                if (start_right and plus_pi_2) {  // starts in it and go to the left half
                    int yl = ceil(y1 - eps);
                    int yr = get_yl_yr(p).second;
                    ranges.emplace_back(yl, yr);
                }
                if (minus_pi_2 and end_right) {  // come from the left half and ends in it
                    int yl = get_yl_yr(p).first;
                    int yr = ceil(y2 - eps);
                    ranges.emplace_back(yl, yr);
                }
            }
            for (auto range : ranges) {
                int yl, yr; tie(yl, yr) = range;
                REP3 (y, yl, yr) {
                    int xr = get_xl_xr(p, y).second;
                    imos.emplace_back(y, xr, -1);
                }
            }
        }

    }

    sort(ALL(imos));
    imos.erase(unique(ALL(imos)), imos.end());
    ll cnt = 0;
    for (int i = 0; i < imos.size(); ) {
        int y = get<0>(imos[i]);
        int last = - size;
        int acc = 0;
        int cnt_y = 0;
        for (; i < imos.size() and get<0>(imos[i]) == y; ++ i) {
            if (acc < 0) continue;
            int x, delta; tie(ignore, x, delta) = imos[i];
            if (acc) cnt_y += x - last;
            last = x;
            acc += delta;
        }
        if (acc == 0) {
            cnt += cnt_y;
        } else {
            cnt += solve_for_y(n, ps, y);
        }
    }
    return cnt;
}

int main() {
    int n; cin >> n;
    vector<point_t> ps(n);
    REP (i, n) {
        int x, y; cin >> x >> y;
        ps[i] = { y, x };
    }
    cout << solve(n, ps) << endl;
    return 0;
}
```
