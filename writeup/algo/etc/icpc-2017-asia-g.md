---
layout: post
alias: "/blog/2017/12/19/icpc-2017-asia-g/"
date: "2017-12-19T03:49:23+09:00"
tags: [ "competitive", "writeup", "icpc", "icpc-asia", "implementation", "linear-aldgebra", "geometry" ]
---

# AOJ 1384 / ACM-ICPC 2017 Asia Tsukuba Regional Contest: G. Rendezvous on a Tetrahedron

-   <http://judge.u-aizu.ac.jp/onlinejudge/description.jsp?id=1384>
-   <http://judge.u-aizu.ac.jp/onlinejudge/cdescription.jsp?cid=ICPCOOC2017&pid=G>

## problem

正四面体がある。頂点$A$から始めて向き$\theta$に距離$l$だけ表面上を進んだ後にいる面を$f(\theta, l)$とする。これを求めよ。特に組$(\theta, l)$がふたつ与えられるので$f$による像が一致するか求めよ。

## solution

展開図を書いて繰り返す。$4$色の正三角形からなる模様が現れ、位置$(x, y)$がどの色かを答える。
適切に座標変換をして剰余を取り$8$つに場合分け。
$O(1)$。

## implementation

``` c++
#include <bits/stdc++.h>
using namespace std;

constexpr double eps = 1e-12;
double deg2rad(double x) { return x / 360 * (2 * M_PI); }
double frem(double x, double y) { return fmod(fmod(x, y) + y + eps, y); }
enum face_t { ABC, ACD, ADB, BCD };

face_t get_face() {
    string xy; int d, l; cin >> xy >> d >> l;
    double face_theta =
        xy == "BC" ? 0 :
        xy == "CD" ? 60 :
        xy == "DB" ? 120 :
        NAN;
    double theta = deg2rad(face_theta + d);
    double x = l * cos(theta);
    double y = l * sin(theta);
    double z60 = x + y / sqrt(3);
    double z120 = - x + y / sqrt(3);
    z60 = frem(z60, 2);
    z120 = frem(z120, 2);
    double w = (z60 + z120) * (sqrt(3) / 2);
    return
        w < sqrt(3) / 2 ?
            ACD :
        w < sqrt(3) ?
            z60 > 1 ? ABC :
            z120 > 1 ? ADB :
            BCD :
        w < 3 * sqrt(3) / 2 ?
            z60 < 1 ? ABC :
            z120 < 1 ? ADB :
            BCD :
        ACD;
}

int main() {
    face_t a = get_face();
    face_t b = get_face();
    cout << (a == b ? "YES" : "NO") << endl;
    return 0;
}
```
