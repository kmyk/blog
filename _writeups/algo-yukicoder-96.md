---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/96/
  - /blog/2017/01/07/yuki-96/
date: "2017-01-07T00:19:00+09:00"
tags: [ "competitive", "writeup", "yukicoder", "bucket-method", "lie", "farthest-point-pair", "randomized-algorithm" ]
"target_url": [ "http://yukicoder.me/problems/no/96" ]
---

# Yukicoder No.96 圏外です。

また乱択で嘘っぽい解法を投げた。落とされそう。

## solution

バケット法で適当に連結成分に切り分け、木の直径の要領で乱択による最遠点対。

バケット法。
$x_i, y_i \in [- 10000, + 10000]$であるが、接続性グラフの辺の条件は$d(i,j) \le 10$であるので、近い位置同士のみ見ればよい。
$10$や$20$ぐらいの数で割った商で同値類を作って空間を適当に小さく切り、隣接する区間同士の頂点のみ接続判定する。
これで連結成分が出る。union-find木は不要で、DFS/BFSでよい。ただしstackの容量の問題からloopに展開する必要があるかも。

最遠点対。
これは厳密にやるのは面倒で、愚直だと$O(N^2)$と間に合わない。
そこで(グラフは木ではないし距離もEuclid距離だが)木の直径の要領で乱択で求める。
つまり始点$i$を適当に決め、その$i$からの最遠点$j$、$j$からの最遠点$k$をそれぞれ$O(N)$で求め、点対$(j,k)$を候補とする。
$1$回では最遠点対が得られるとは限らないので、制限時間に合わせてたくさん試す。
`random_shuffle`して前から`min<int>(300, acc.size())`個のように見るようにするとよさげ。


## implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <functional>
#include <cmath>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using namespace std;
template <class T> void setmax(T & a, T const & b) { if (a < b) a = b; }
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }
bool is_on_field(int y, int x, int h, int w) { return 0 <= y and y < h and 0 <= x and x < w; }
int main() {
    int n; cin >> n;
    vector<int> x(n), y(n);
    repeat (i,n) {
        cin >> x[i] >> y[i];
        x[i] += 10000;
        y[i] += 10000;
        assert (0 <= y[i] and y[i] <= 20000);
        assert (0 <= x[i] and x[i] <= 20000);
    }
    function<double (int, int)> dist = [&](int i, int j) { return hypot(x[i] - x[j], y[i] - y[j]); };
    function<int (int, vector<int> const &)> farthest = [&](int i, vector<int> const & acc) {
        return *whole(max_element, acc, [&](int j, int k) { return dist(i, j) < dist(i, k); });
    };
    const int Q = 20;
    const int K = 20000 / Q + 1;
    assert (20000 / Q < K);
    auto bucket = vectors(K, K, vector<int>());
    repeat (i,n) bucket[y[i] / Q][x[i] / Q].push_back(i);
    double ans = 1;
    vector<bool> used(n);
    repeat (i,n) if (not used[i]) {
        vector<int> acc; {
            int it = 0;
            acc.push_back(i);
            used[i] = true;
            while (it < acc.size()) {
                int j = acc[it]; ++ it;
                for (int dy : { -1, 0, 1 }) {
                    for (int dx : { -1, 0, 1 }) {
                        int ny = y[j] / Q + dy;
                        int nx = x[j] / Q + dx;
                        if (is_on_field(ny, nx, K, K)) {
                            for (int k : bucket[ny][nx]) if (not used[k] and dist(j, k) <= 10) {
                                acc.push_back(k);
                                used[k] = true;
                            }
                        }
                    }
                }
            }
        }
        if (acc.size() < 300) {
            repeat (j, acc.size()) {
                repeat (i, j+1) {
                    setmax(ans, dist(acc[i], acc[j]) + 2);
                }
            }
        } else {
            whole(random_shuffle, acc);
            repeat (i, min<int>(300, acc.size())) {
                int j = farthest(i, acc);
                int k = farthest(j, acc);
                setmax(ans, dist(j, k) + 2);
            }
        }
    }
    printf("%.9lf\n", ans);
    return 0;
}
```

<hr>

-   2017年  2月  6日 月曜日 17:41:03 JST
    -   落ちてたので修正。小さい連結成分は愚直$O(N^2)$で総当たりするようにした
