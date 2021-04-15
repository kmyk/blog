---
layout: post
redirect_from:
  - /writeup/algo/etc/icpc-2016-domestic-f/
  - /blog/2016/06/27/icpc-2016-domestic-f/
date: 2016-06-27T13:02:00+09:00
tags: [ "competitive", "writeup", "icpc" ]
---

# ACM-ICPC 2016 国内予選 F: 文字解読

-   <http://icpcsec.storage.googleapis.com/icpc2016-domestic/problems/all_ja.html#section_F>
-   <http://icpc.iisf.or.jp/past-icpc/domestic2016/judgedata/F/>

問題文が難解。

類問: [Yukicoder No.348 カゴメカゴメ](http://yukicoder.me/problems/no/348)

## solution

木を作って同型性判定する。木を作るのは$O(HW)$。同型性判定は$O(N^2\log N)$でやった。

画像の成分の包含関係をグラフにする。これ特に(ラベルなしの)根付き木になる。白黒の別は、根となる背景連結成分の白から始めて交互に白黒が並ぶので、頂点の深さから一意に定まる。
この木は単に作ればよい。

あとはこの木の同型性判定をする。適当に正規化して比較すれば間に合う。
単純に`((()())(()))`のような文字列に落とすだけでよい。hash関数でも噛ましておけば計算量は落とせるだろう。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <set>
#include <functional>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) y) { return (f)(begin(y), end(y), ## __VA_ARGS__); })(x)
using namespace std;
template <typename T, typename X> auto vectors(T a, X x) { return vector<T>(x, a); }
template <typename T, typename X, typename Y, typename... Zs> auto vectors(T a, X x, Y y, Zs... zs) { auto cont = vectors(a, y, zs...); return vector<decltype(cont)>(x, cont); }

const int dy[] = { -1, 1, 0, 0, -1, 1, -1, 1 };
const int dx[] = { 0, 0, 1, -1, -1, 1, 1, -1 };

vector<vector<bool> > load_image() {
    int h, w; cin >> h >> w;
    if (h == 0 and w == 0) return vector<vector<bool> >();
    vector<vector<bool> > f = vectors(false, h+2, w+2);
    repeat (y,h) repeat (x,w) {
        char c; cin >> c;
        f[y+1][x+1] = c == '#';
    }
    return f;
}

vector<set<int> > make_tree(vector<vector<bool> > const & f) {
    int h = f.size();
    int w = f.front().size();
    vector<vector<int> > k = vectors(-1, h, w);
    vector<set<int> > g;
    function<void (int, int, int)> dfs = [&](int y, int x, int cur_k) {
        k[y][x] = cur_k;
        repeat (i, f[y][x] ? 8 : 4) {
            int ny = y + dy[i];
            int nx = x + dx[i];
            if (ny < 0 or h <= ny or nx < 0 or w <= nx) continue;
            if (f[ny][nx] == f[y][x]) {
                if (k[ny][nx] == -1) {
                    dfs(ny, nx, cur_k);
                }
            } else {
                if (k[ny][nx] != -1) {
                    g[k[ny][nx]].insert(k[y][x]);
                }
            }
        }
    };
    repeat (y,h) repeat (x,w) if (k[y][x] == -1) {
        g.emplace_back();
        dfs(y, x, g.size() - 1);
    }
    return g;
}

string format_tree(int i, int p, vector<set<int> > const & g) {
    vector<string> ts;
    for (int j : g[i]) if (j != p) {
        ts.push_back(format_tree(j, i, g));
    }
    whole(sort, ts);
    string s;
    s += '(';
    for (string t : ts) s += t;
    s += ')';
    return s;
}

bool is_isomorphic(vector<set<int> > const & t1, vector<set<int> > const & t2) {
    return format_tree(0, -1, t1) == format_tree(0, -1, t2);
}

int main() {
    while (true) {
        auto g1 = load_image(); if (g1.empty()) break;
        auto g2 = load_image();
        auto t1 = make_tree(g1);
        auto t2 = make_tree(g2);
        cout << (is_isomorphic(t1, t2) ? "yes" : "no") << endl;
    }
    return 0;
}
```
