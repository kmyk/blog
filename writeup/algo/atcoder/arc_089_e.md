---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc_089_e/
  - /writeup/algo/atcoder/arc-089-e/
  - /blog/2018/01/23/arc-089-e/
date: "2018-01-23T19:41:44+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "graph", "construction" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc089/tasks/arc089_c" ]
---

# AtCoder Regular Contest 089: E - GraphXY

すぐに思い付いたのに頂点番号に$+1$するのを忘れてWAをたくさん生やした。Pythonで書き始めて途中でC++に切り替えたときに混入したバグだった。

問題は好き。

## solution

$S \overset{X}{\to} \cdot \overset{X}{\to} \cdot \overset{X}{\to} \dots$ のような鎖と $\dots \overset{Y}{\to} \cdot \overset{Y}{\to} \cdot \overset{Y}{\to} T$ のような鎖を用意し、これらの点の間を適当に繋ぐ。$O(AB \cdot (\max d\_{x, y})^2)$。

まず$S \to T$のpathを考えたときその重みは$ax + by + c$の形をしている。
それぞれの対$(x, y)$について$ax + by + c = d\_{x, y}$となるような$(a, b, c)$を見つけてそのようなpathを作っていけばよさそう。
しかし別の$(x', y')$の制約を壊してはならず、また使用する頂点数が$300$以下でなければならない。
後者は先に示したような鎖を使って$a, b$を設定する部分を全てのpathで共有しそれらを繋ぐ中央の辺で$c$を設定することで解決できる。
前者は$(x, y)$から$(a, b, c)$を決定するのでなく$(a, b, c)$で可能なものを総当たりすることで解決できる。
$(a, b)$を固定すれば使う$c$はひとつたけでよく、多重辺がだめなので辺を共有するならばむしろひとつでなければならないことに注意。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
using namespace std;
template <class T> inline void chmax(T & a, T const & b) { a = max(a, b); }
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

int main() {
    // input
    int a, b; cin >> a >> b;
    auto d = vectors(a, b, int());
    REP (x, a) REP (y, b) cin >> d[x][y];

    // solve
    constexpr int n = 300;
    constexpr int max_d = 100;
    constexpr int max_c = 100;
    // // prepare the structure
    vector<tuple<int, int, char> > char_edge;
    vector<int> xs(max_d + 1);
    vector<int> ys(max_d + 1);
    xs[0] = 0;
    ys[0] = n - 1;
    REP (i, max_d) {
        xs[i + 1] = xs[i] + 1;
        ys[i + 1] = ys[i] - 1;
        char_edge.emplace_back(xs[i], xs[i + 1], 'X');
        char_edge.emplace_back(ys[i + 1], ys[i], 'Y');
    }
    // // construct the required graph
    auto used = vectors(a, b, false);
    vector<tuple<int, int, int> > int_edge;
    REP (i, max_d + 1) REP (j, max_d + 1) if (i + j <= max_d) {
        int c = 0;
        REP (x, a) REP (y, b) {
            int f = i * (x + 1) + j * (y + 1);
            chmax(c, d[x][y] - f);
        }
        if (c > max_c) continue;
        int_edge.emplace_back(xs[i], ys[j], c);
        REP (x, a) REP (y, b) {
            int f = i * (x + 1) + j * (y + 1);
            assert (d[x][y] <= f + c);
            if (f + c == d[x][y]) {
                used[x][y] = true;
            }
        }
    }
    // // check the result
    bool possible = true;
    REP (x, a) REP (y, b) {
        if (not used[x][y]) {
            possible = false;
        }
    }

    // output
    cout << (possible ? "Possible" : "Impossible") << endl;
    if (possible) {
        int m = int_edge.size() + char_edge.size();
        cout << n << ' ' << m << endl;
        for (auto e : char_edge) {
            cout << get<0>(e) + 1 << ' ' << get<1>(e) + 1 << ' ' << get<2>(e) << endl;
        }
        for (auto e : int_edge) {
            cout << get<0>(e) + 1 << ' ' << get<1>(e) + 1 << ' ' << get<2>(e) << endl;
        }
        int s = xs[0];
        int t = ys[0];
        cout << s + 1 << ' ' << t + 1 << endl;
    }
    return 0;
}
```
