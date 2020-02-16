---
layout: post
alias: "/blog/2016/06/12/jag2016-domestic2-c/"
date: 2016-06-12T22:30:42+09:00
tags: [ "competitive", "writeup", "icpc", "jag", "imos-method" ]
"target_url": [ "http://acm-icpc.aitea.net/index.php?2016%2FPractice%2F%E6%A8%A1%E6%93%AC%E5%9B%BD%E5%86%85%E4%BA%88%E9%81%B8B" ]
---

# JAG 模擬国内予選 2016: C - カーテン

コンテスト中は先輩氏が書いた。
順番的には私だったが、私がやるとバグらせそうだったので代わってもらった。

## solution

$H \times W = 40000 \times 40000$の空間を持ってimos法で愚直にやる。
窓の境界線だけ向きを忘れて記録して、壁の端から見ていって、境界線と奇数回交わった場所は窓、そうでないなら壁。
$1$ファイルあたり$2,3$分かかるけど、国内予選は$3$時間あるので何の問題もない。

遅いのが嫌なら各列ごとに存在する縦線の位置をlistで持って走れば$H \times N = 40000 \times 100$になる。隣接行列でなく隣接listを持つ感じ。
座標圧縮は実装がつらそうなのでやめた方がいいと思います。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <array>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
const int offset = 20000;
const int width = 20000 + offset;
int signof(int y) {
    return y < 0 ? -1 : y > 0 ? 1 : 0;
}
int main() {
    while (true) {
        int n; cin >> n;
        if (n == 0) break;
        vector<vector<bool> > f(width, vector<bool>(width+1)); { // imos
            vector<int> xs(n), ys(n);
            repeat (i,n) {
                cin >> xs[i] >> ys[i];
                xs[i] += offset;
                ys[i] += offset;
            }
            repeat (i,n) {
                int j = (i+1)%n;
                int dx = signof(xs[j] - xs[i]);
                int dy = signof(ys[j] - ys[i]);
                if (dx) continue;
                assert (dy);
                int x = xs[i];
                int y = ys[i];
                while (y != ys[j]) {
                    int ny = min(y, y + dy);
                    f[ny][x] = true;
                    y += dy;
                }
            }
        }
        int xl, xr, yl, yr; {
            array<int,4> a, b; repeat (i,4) cin >> a[i] >> b[i];
            xl = *min_element(a.begin(), a.end()) + offset;
            xr = *max_element(a.begin(), a.end()) + offset;
            yl = *min_element(b.begin(), b.end()) + offset;
            yr = *max_element(b.begin(), b.end()) + offset;
        }
        int ans = 0;
        repeat (y,width) {
            int acc = 0;
            repeat (x,width+1) {
                if (f[y][x]) acc ^= 1;
                if (acc and not (yl <= y and y < yr and xl <= x and x < xr)) { // not covered with the curtain
                    ans += 1;
                }
            }
        }
        cerr << ans << endl;
        cout << ans << endl;
    }
    return 0;
}
```
