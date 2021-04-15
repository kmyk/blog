---
layout: post
redirect_from:
  - /writeup/algo/atcoder/tenka1-2016-quala-d/
  - /blog/2016/07/30/tenka1-2016-quala-d/
date: "2016-07-30T23:24:33+09:00"
tags: [ "competitive", "wirteup", "atcoder", "tenka1-programmer-contest", "graph", "tree", "implementation" ]
"target_url": [ "https://beta.atcoder.jp/contests/tenka1-2016-quala/tasks/tenka1_2016_qualD_a" ]
---

# 天下一プログラマーコンテスト2016予選A: D - グラフィカルグラフ

やるだけ面倒の問題だと思ったが、座圧とか乱択とか色々できるらしく良い問題である。

## solution

適当な愚直で実装すればよい。
画面幅の制約$H, W \le 100$は$N \le 26$であるため(明らかな無駄を発生させない限り)ないものと見なせる。

## implementation

各部分木についてその部分木から生成される出力のAABBやその他を再帰的に葉から計算し、それを元に根から出力を構成していった。

-   > 頂点を表す文字は、別の頂点を表す文字と縦または横に隣接してはならない。

の制約を見落としていてWAを吐いた。

``` c++
#include <iostream>
#include <vector>
#include <map>
#include <functional>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;

enum dir_t {
    FOR = 0,
    LEFT = 1,
    BACK = 2,
    RIGHT = 3,
};
dir_t rot(dir_t d) {
    return dir_t((int(d) + 1) % 4);
}
dir_t tor(dir_t d) {
    return dir_t((int(d) + 3) % 4);
}
int dy_of(dir_t d) {
    switch (d) {
        case LEFT: return -1;
        case RIGHT: return 1;
        default: return 0;
    }
}
int dx_of(dir_t d) {
    switch (d) {
        case FOR: return 1;
        case BACK: return -1;
        default: return 0;
    }
}

int main() {
    // input
    int n; cin >> n;
    vector<vector<int> > g(n);
    repeat (i,n-1) {
        char v, w; cin >> v >> w;
        g[v-'A'].push_back(w-'A');
        g[w-'A'].push_back(v-'A');
    }

    // prepare
    /* layout
     *    m = 5
     *  <   >
     *  E-D  ^ l = 2
     *    |  v           for B, from A
     * ~--B-C
     *         r = 0
     */
    vector<int> l(n, -1);
    vector<int> m(n, -1);
    vector<int> r(n, -1);
    vector<map<int,dir_t> > dir(n);
    vector<map<int,int> > dist(n);
    vector<int> offset(n);
    function<void (int, int)> dfs_prepare = [&](int x, int p) {
        vector<int> children;
        for (int y : g[x]) if (y != p) children.push_back(y);
        for (int y : children) dfs_prepare(y, x);
        if (children.size() == 0) {
            /* ~x
             */
            l[x] = 0;
            m[x] = 1;
            r[x] = 0;
        } else if (children.size() == 1) {
            /*    yyy
             * ~x-yyy
             *    yyy
             */
            int y = children[0];
            dir[x][y] = FOR;
            dist[x][y] = 1;
            l[x] = l[y];
            m[x] = m[y] + dist[x][y] + 1;
            r[x] = r[y];
        } else if (children.size() == 2) {
            /*  yyyy
             *  yyyy
             * ~--x
             *    |
             *    z
             */
            int y = children[0];
            int z = children[1];
            dir[x][y] = LEFT;
            dir[x][z] = RIGHT;
            dist[x][y] = 1;
            dist[x][z] = 1;
            l[x] = m[y] + dist[x][y];
            r[x] = m[z] + dist[x][z];
            offset[x] = max(l[y], r[z]);
            m[x] = offset[x] + 1 + max(r[y], l[z]);
        } else if (children.size() == 3) {
            /*  yyy
             *  yyy
             *   |
             * ~-x----ww
             *  zzzzzzww
             *  zzzzzz
             */
            int y = children[0];
            int z = children[1];
            int w = children[2];
            dir[x][y] = LEFT;
            dir[x][z] = RIGHT;
            dir[x][w] = FOR;
            dist[x][y] = 1;
            dist[x][z] = 1;
            l[x] = max(m[y] + dist[x][y], l[w]);
            r[x] = max(m[z] + dist[x][z], r[w]);
            offset[x] = max(l[y], r[z]);
            dist[x][w] = 1 + max(r[y], l[z]);
            m[x] = offset[x] + 1 + dist[x][w] + m[w];
        } else {
            assert (false);
        }
    };
    int root = -1;
    repeat (i,n) {
        if (g[i].size() != 4) {
            root = i;
            break;
        }
    }
    dfs_prepare(root, -1);

    // construct
    int width = m[root];
    int height = l[root] + 1 + r[root];
    assert (height <= 100);
    assert (width  <= 100);
    vector<string> f(height, string(width, '.'));
    function<void (int, int, int, int, dir_t)> dfs_construct = [&](int i, int p, int y, int x, dir_t d) {
        char c = (p == -1) ? '.' : (d == FOR or d == BACK) ? '-' : '|';
        repeat (j,offset[i]) {
            assert (f[y][x] == '.');
            f[y][x] = c;
            y += dy_of(d);
            x += dx_of(d);
        }
        assert (f[y][x] == '.');
        f[y][x] = i + 'A';
        for (int j : g[i]) if (j != p) {
            dir_t nd = dir[i][j] == LEFT ? rot(d) : dir[i][j] == RIGHT ? tor(d) : d;
            char nc = (nd == FOR or nd == BACK) ? '-' : '|';
            int ny = y + dy_of(nd);
            int nx = x + dx_of(nd);
            repeat (k,dist[i][j]) {
                assert (f[ny][nx] == '.');
                f[ny][nx] = nc;
                ny += dy_of(nd);
                nx += dx_of(nd);
            }
            dfs_construct(j, i, ny, nx, nd);
        }
    };
    dfs_construct(root, -1, l[root], 0, FOR);

    // output
    cout << height << ' ' << width << endl;
    for (auto it : f) cout << it << endl;
    return 0;
}
```
