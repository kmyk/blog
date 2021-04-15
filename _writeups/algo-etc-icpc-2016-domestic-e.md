---
layout: post
redirect_from:
  - /writeup/algo/etc/icpc-2016-domestic-e/
  - /blog/2016/06/27/icpc-2016-domestic-e/
date: 2016-06-27T13:01:58+09:00
tags: [ "competitive", "writeup", "icpc", "geometry", "graph" ]
---

# ACM-ICPC 2016 国内予選 E: 3D プリント

-   <http://icpcsec.storage.googleapis.com/icpc2016-domestic/problems/all_ja.html#section_E>
-   <http://icpc.iisf.or.jp/past-icpc/domestic2016/judgedata/E/>

悪意のある図。問題文を丁寧に読めばやるだけになる。

## solution

-   >   各立方体は 0 個，1 個 または 2 個の立方体と重なることがあるが，3 個以上とは重ならない．
-   >   ある立方体が 2 個の立方体と重なるとき，その 2 個の立方体は重ならない．
-   >   面や辺や頂点で接触するだけで重なりのない 2 個の立方体はない．

であるので、グラフに落としてやる。$O(N^2)$ぐらいで適当にやる。

各立方体を頂点として接続関係のグラフを作る。
各辺には交差し埋没した表面積を持たせる。
各頂点の次数は高々$2$であるので、道グラフと閉路グラフのみからなるグラフとなる。
このグラフ中から以下を列挙し、その中で重みが最大のものから答えを構成すればよい。

-   長さ$k$の閉路 ($k = 1,2$のものも許容する)
-   長さ$k-1$の道で始点と終点が隣接しないもの

特に$k = 2$のときに注意。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <functional>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
template <class T> void setmin(T & a, T const & b) { if (b < a) a = b; }
const int inf = 1e9+7;
int main() {
    while (true) {
        // input
        int n, k, s; cin >> n >> k >> s;
        vector<int> x(n), y(n), z(n); repeat (i,n) cin >> x[i] >> y[i] >> z[i];
        if (n == 0 and k == 0 and s == 0) break;
        // geometry
        auto is_connected = [&](int i, int j) {
            int dx = abs(x[j] - x[i]);
            int dy = abs(y[j] - y[i]);
            int dz = abs(z[j] - z[i]);
            return dx <= s and dy <= s and dz <= s;
        };
        auto intersecting_area = [&](int i, int j) {
            if (not is_connected(i, j)) return 0;
            int dx = s - abs(x[j] - x[i]);
            int dy = s - abs(y[j] - y[i]);
            int dz = s - abs(z[j] - z[i]);
            return 2 * (dx * dy + dy * dz + dz * dx);
        };
        // make graph
        vector<vector<int> > g(n);
        repeat (i,n) repeat (j,n) if (i != j) {
            if (is_connected(i, j)) g[i].push_back(j);
        }
        // find paths/cycles and the area
        function<int (int, int, int, int)> dfs = [&](int i, int prev, int depth, int first) {
            if (depth == k) {
                if (3 <= k and is_connected(i, first)) {
                    return 6*s*s - intersecting_area(i, first);
                }
                return 6*s*s;
            } else {
                int ans = inf;
                for (int j : g[i]) if (j != prev) {
                    setmin(ans, 6*s*s - intersecting_area(i, j) + dfs(j, i, depth + 1, first));
                }
                return ans;
            }
        };
        // output
        int ans = inf;
        repeat (i,n) setmin(ans, dfs(i, -1, 1, i));
        if (ans == inf) ans = -1;
        cout << ans << endl;
    }
    return 0;
}
```
