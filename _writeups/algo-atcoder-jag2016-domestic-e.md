---
layout: post
redirect_from:
  - /writeup/algo/atcoder/jag2016-domestic-e/
  - /blog/2016/04/25/jag2016-domestic-e/
date: 2016-04-25T21:22:18+09:00
tags: [ "competitive", "writeup", "atcoder", "jag", "icpc", "geometry" ]
"target_url": [ "https://beta.atcoder.jp/contests/jag2016-domestic/tasks/jag2016secretspring_e" ]
---

# JAG Contest 2016 Domestic E - 選挙活動

幾何ゲーはだめ

## solution

候補点を絞って全部試す。
有権者から障害物の各頂点へ半直線を投げ、それら半直線どうしの交点の全てを候補点とすればよい。

## implementation

>   多角形の頂点または有権者のいる場所の座標のうち3点が同一直線状に存在することはない．

等の*やさしさ*がいくらか存在する。

コンテスト終了後であるが、[2016/Practice/模擬国内予選A/問題文とデータセット - ACM-ICPC Japanese Alumni Group](http://acm-icpc.aitea.net/index.php?2016%2FPractice%2F%E6%A8%A1%E6%93%AC%E5%9B%BD%E5%86%85%E4%BA%88%E9%81%B8A%2F%E5%95%8F%E9%A1%8C%E6%96%87%E3%81%A8%E3%83%87%E3%83%BC%E3%82%BF%E3%82%BB%E3%83%83%E3%83%88)でテストケースが全て公開されているので、これを参考にすることができる。

### visualizer

``` python
#!/usr/bin/env python3
import math
import cairo

OFFSET = 20
WIDTH, HEIGHT = 40, 40
MARGIN = 1
SCALE = 10

# input
n, m = map(int,input().split())
polygons = []
for _ in range(n):
    l = int(input())
    polygon = []
    for _ in range(l):
        x, y = map(int,input().split())
        polygon.append((x, y))
    polygons.append(polygon)
points = []
for _ in range(m):
    x, y = map(int,input().split())
    points.append((x, y))

# prepare
surface = cairo.ImageSurface(cairo.FORMAT_ARGB32, (WIDTH + 2*MARGIN) * SCALE, (HEIGHT + 2*MARGIN) * SCALE)
ctx = cairo.Context(surface)
ctx.scale(SCALE, SCALE)
ctx.translate(MARGIN + OFFSET, MARGIN + OFFSET)

# render
for polygon in polygons:
    x, y = polygon[0]
    ctx.move_to(x, y)
    for x, y in polygon[1:]:
        ctx.line_to(x, y)
    ctx.close_path ()
    ctx.set_source_rgb(0, 0, 1)
    ctx.set_line_width(0.2)
    ctx.stroke_preserve()
    ctx.set_source_rgba(0, 0, 1, 0.5)
    ctx.fill()
for x, y in points:
    ctx.arc(x, y, 0.6, 0, 2*math.pi)
    ctx.set_source_rgb(0, 0, 0)
    ctx.set_source_rgb(1, 0, 0)
    ctx.set_line_width(0.1)
    ctx.stroke_preserve()
    ctx.set_source_rgba(1, 0, 0, 0.5)
    ctx.fill()

# output
surface.write_to_png("/dev/stdout")
```

### code

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <complex>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
template <class T> bool setmax(T & l, T const & r) { if (not (l < r)) return false; l = r; return true; }
using namespace std;

typedef complex<double> point;
struct circle { point c; double r; };
struct line { point s, t; };
struct segment { point s, t; };
struct ray { point s, t; };

const double eps = 1e-6;

namespace std {
    bool operator < (point const & a, point const & b) {
        return real(a) != real(b) ? real(a) < real(b) : imag(a) < imag(b);
    }
}
double   dot(point p, point q) { return real(p) * real(q) + imag(p) * imag(q); }
double cross(point p, point q) { return real(p) * imag(q) - imag(p) * real(q); }
int ccw(point a, point b, point c) { double z = cross(b - a, c - a); return z > eps ? 1 : z < - eps ? -1 : 0; }

bool do_intersect(point a, line b) {
    return ccw(0, a - b.s, b.t - b.s) == 0;
}
bool do_intersect(line a, point b) {
    return do_intersect(b, a);
}
bool is_overwraped(line a, line b) {
    return do_intersect(a.s, b)
        and do_intersect(a.t, b);
}
bool is_parallel(line a, line b) {
    return ccw(0, a.t - a.s, b.t - b.s) == 0;
}
bool do_intersect(line a, line b) { // don't be overwrapped
    return not is_parallel(a, b)
        and not is_overwraped(a, b);
}
point intersection(line a, line b) {
    assert (do_intersect(a, b));
    double p = cross(a.t - a.s, b.t - b.s);
    double q = cross(a.t - a.s, a.t - b.s);
    return (q / p) * (b.t - b.s) + b.s;
}

template <typename T, typename U>
bool do_intersect_linelikes(T const & a, U const & b) {
    if (not do_intersect(to_line(a), to_line(b))) return false;
    point c = intersection(to_line(a), to_line(b));
    return do_intersect(a, c)
        and do_intersect(b, c);
}
template <typename T, typename U>
point intersection_linelikes(T const & a, U const & b) {
    assert (do_intersect(a, b));
    return intersection(to_line(a), to_line(b));
}

line to_line(segment a) {
    return { a.s, a.t };
}
bool do_intersect(point a, segment b) {
    return abs(cross(b.t - b.s, a - b.s)) < eps
        and dot(b.t - b.s, a - b.s) > - eps
        and dot(b.s - b.t, a - b.t) > - eps;
}
bool do_intersect(segment a, point b) {
    return do_intersect(b, a);
}
bool is_overwraped(segment a, segment b) {
    return do_intersect(a.s, b)
        and do_intersect(a.t, b);
}
bool do_intersect(segment a, segment b) {
    return do_intersect_linelikes(a, b);
}
point intersection(segment a, segment b) {
    return intersection_linelikes(a, b);
}

line to_line(ray a) {
    return { a.s, a.t };
}
bool do_intersect(point a, ray b) {
    return abs(cross(b.t - b.s, a - b.s)) < eps
        and dot(b.t - b.s, a - b.s) > - eps;
}
bool do_intersect(ray a, point b) {
    return do_intersect(b, a);
}
bool is_overwraped(ray a, ray b) {
    return (do_intersect(a.s, b) and do_intersect(a.t, b))
        or (do_intersect(b.s, a) and do_intersect(b.t, a));
}
bool do_intersect(ray a, ray b) {
    return do_intersect_linelikes(a, b);
}
point intersection(ray a, ray b) {
    return intersection_linelikes(a, b);
}

struct polygon { vector<point> ps; };
segment nth_segment(polygon const & a, int i) {
    int j = (i+1) % a.ps.size();
    return { a.ps[i], a.ps[j] };
}
bool do_intersect(ray a, segment b) { return do_intersect_linelikes(a, b); }
bool do_intersect(segment a, ray b) { return do_intersect_linelikes(a, b); }
point intersection(ray a, segment b) { return intersection_linelikes(a, b); }
point intersection(segment a, ray b) { return intersection_linelikes(a, b); }
template <typename T>
vector<point> intersections_polygon_linelike(polygon const & a, T const & b) {
    vector<point> result;
    repeat (i, a.ps.size()) {
        if (do_intersect(nth_segment(a, i), b)) {
            result.push_back(intersection(nth_segment(a, i), b));
        }
    }
    return result;
}
bool do_intersect(polygon const & a, ray const & b) {
    return not intersections_polygon_linelike(a, b).empty();
}
bool do_intersect(polygon const & a, point const & b) {
    ray c = { b, b + point(1, 0) };
    return intersections_polygon_linelike(a, c).size() % 2 == 1;
}
bool do_intersect_strict(polygon const & a, point const & b) {
    repeat (i, a.ps.size()) {
        if (do_intersect(nth_segment(a, i), b)) {
            return false; // when the point is on a segment of the polygon
        }
    }
    return do_intersect(a, b);
}
bool do_intersect_strict(polygon const & a, segment const & b) { // the boundary is not included
    vector<point> ps = intersections_polygon_linelike(a, b);
    for (point p : ps) {
        bool ignored = false;
        if (abs(p - b.s) < eps or abs(p - b.t) < eps) {
            ignored = true;
        }
        if (not ignored) {
            for (point q : a.ps) {
                if (abs(p - q) < eps) {
                    ignored = true; // when the intersection point is one of the vertex of the polygon
                    break;
                }
            }
        }
        if (not ignored) return true;
    }
    return false;
}


int main() {
    // input
    int n, m; cin >> n >> m;
    vector<polygon> polygons(n);
    repeat (i,n) {
        int l; cin >> l;
        polygons[i].ps.resize(l);
        repeat (j,l) {
            double x, y; cin >> x >> y;
            polygons[i].ps[j] = { x, y };
        }
    }
    vector<point> points(m);
    repeat (i,m) {
        double x, y; cin >> x >> y;
        points[i] = { x, y };
    }
    // make candidates
    vector<point> candidates; {
        for (point p : points) {
            candidates.push_back(p);
        }
        vector<ray> rays;
        for (point p : points) {
            for (polygon const & poly : polygons) {
                for (point q : poly.ps) {
                    rays.push_back((ray) { p, q });
                }
            }
        }
        int l = rays.size();
        repeat (i,l) {
            repeat (j,i) {
                if (do_intersect(rays[i], rays[j])) {
                    candidates.push_back(intersection(rays[i], rays[j]));
                }
            }
        }
    }
    // filter candidates
    sort(candidates.begin(), candidates.end());
    candidates.erase(unique(candidates.begin(), candidates.end()), candidates.end());
    candidates.erase(remove_if(candidates.begin(), candidates.end(), [&](point const & p) {
        for (polygon const & poly : polygons) {
            if (do_intersect_strict(poly, p)) {
                return true;
            }
        }
        return false;
    }), candidates.end());
    // make the answer
    int ans = 0;
    for (point p : candidates) {
        int cnt = 0;
        for (point q : points) {
            bool visible = true;
            segment l = { p, q };
            for (polygon const & poly : polygons) {
                if (do_intersect_strict(poly, l)) {
                    visible = false;
                    break;
                }
            }
            if (visible) ++ cnt;
        }
        setmax(ans, cnt);
    }
    // output
    cout << ans << endl;
    return 0;
}
```
