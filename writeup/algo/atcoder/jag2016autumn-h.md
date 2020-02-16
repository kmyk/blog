---
layout: post
redirect_from:
  - /blog/2016/10/11/jag2016autumn-h/
date: "2016-10-11T22:47:11+09:00"
tags: [ "competitive", "writeup", "atcoder", "jag", "icpc", "dp" ]
"target_url": [ "https://beta.atcoder.jp/contests/jag2016autumn/tasks/icpc2016autumn_h" ]
---

# JAG Practice Contest for ACM-ICPC Asia Regional 2016: H - Pipe Fitter and the Fierce Dogs

icpc直前最後の茶会で、全員で束になって挑んで方針まで立てた。
最近みな強くなってるし、次からもこの形式でよい気がしてる。

## problem

$H \times W$の盤面があり、奇数行奇数列目に家がある。
$K$個まで使えるspecial pipeと任意個使えるcommon pipeを使って、これらの家全てに水を供給する。
special pipeは任意の家に直接水を供給する。
common pipeは水が供給されている家$(x, y)$から、家$(x-2, y+2), (x, y+2), (x+2, y+2)$へ繋ぎこの家にも水を供給することができる。
ある家を供給側とするcommon pipeは高々ひとつまで。
common pipeを設置するにはひとつあたりコスト$1$かかり、これを最小化したい。
ただしマス目上に$N$匹の犬がいて、その犬がいるマス上にcommon pipeを敷くのはコストが$2$かかる。

## solution

special pipeを無視してDPして$O(HW)$。犬の周辺だけ処理するようにすれば$O(N)$になりそうだがせずとも通る。
最小費用流は直感的だが間に合わないだろう。

まず行同士の影響ついて。
最終的に全ての家に水が供給されているので、行ごとに独立である。
$H' = 3, \; W' = HW$のように考えてよい。

special pipeについて。
ある家にspecial pipeを繋いだとき、コストの減少は高々$2$であることが言える。
ある家にspecial pipeを繋ぐことによりその家への供給元の家が自由になるが、この家が自由になることによる追加のコストの減少がない。
減少があるとすれば、special pipeを使う家へのpipeのコストは$2$としてよいのでこのpipeは自由に動かせるため、special pipeなしでも減少させることができるためである。
これにより、special pipeなしでのコストを求め、そこへ貪欲にspecial pipeを使用していけばよいことになる。

special pipeなしの場合について。
DPをすればよい。common pipeの繋ぎ方は直線/交差の$2$種類なので、この使い方についての素直なDP。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <set>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;
template <class T> void setmin(T & a, T const & b) { if (b < a) a = b; }
const int inf = 1e9+7;
int main() {
    // input
    int w, h, k; cin >> w >> h >> k; h /= 2;
    int n; cin >> n;
    vector<set<int> > f(h);
    repeat (i,n) {
        int x, y; cin >> x >> y; -- x; -- y;
        if (y % 2 == 0) continue;
        y /= 2;
        f[y].insert(x);
    }
    k -= w/2+1;
    if (k < 0) {
        // output
        cout << -1 << endl;
    } else {
        // compute
        int acc = 0;
        repeat (y,h) {
            vector<int> dp(w+1, inf);
            dp[0] = 0;
            repeat (x,w) {
                if (x % 2 == 0) {
                    ;             setmin<int>(dp[x+1], dp[x]   +     f[y].count(x));
                    if (x-2 >= 0) setmin<int>(dp[x+1], dp[x-2] + 2 * f[y].count(x-1));
                } else {
                    dp[x+1] = dp[x];
                }
            }
            assert (dp[w] != inf);
            acc += dp[w];
        }
        int ans = h * (w/2+1) + acc;
        ans -= 2 * min(acc, k);
        k   -=     min(acc, k);
        ans -=     min(ans, k);
        k   -=     min(ans, k);
        // output
        cout << ans << endl;
    }
    return 0;
}
```
