---
layout: post
redirect_from:
  - /writeup/algo/atcoder/code-festival-2016-qualc-d/
  - /blog/2016/10/23/code-festival-2016-qualc-d/
date: "2016-10-23T23:00:16+09:00"
tags: [ "competitive", "writeup", "atcoder", "codefestival", "dp" ]
"target_url": [ "https://beta.atcoder.jp/contests/code-festival-2016-qualc/tasks/codefestival_2016_qualC_d" ]
---

# CODE FESTIVAL 2016 qual C: D - Friction

通ってほしくて気にしていた人たちがいるのですが、なんとも言えない結果になった。
特に、他に合う機会がない人がおり(私が一方的にそう思っているだけではあるが)一度直接話してみたかったのですが、通過はかなり厳しそうで残念。
来年に期待したい。

## solution

隣接する$2$列ずつのみで考えればよい。$O(WH^2)$。

ある列を一段沈めることの影響は局所的である。
その隣接する列を沈める際のコストにしか影響しない。
このことから、依存を切り、隣接する$2$列のみで考えた結果から全体を導出することを考えたくなる。
実際これはできて、それぞれでのコストを単に足し合わせればよい。
隣接する$2$列で最小コストを達成するような沈め方、例えば`11212122`や`33332222`のような、があれば、それぞれの沈め方はその$2$列の間の順序のみが満たされればよいので、例えば`331313212122`のように、素直に合成可能である。

$W = 2$として$O(H^2)$で解ければよい。
これはDP。
それぞれの列が$y_1,y_2$沈んでいる時に新たに沈める時のコストを$\mathrm{cost}\_{y_1,y_2}$として先に求めておき、
それぞれの列を$y_1,y_2$沈んでいる状況を作るための最小コストを$\mathrm{dp}\_{y_1,y_2}$として求めるのが楽。
それぞれ$O(H^2)$。

## implementation

``` c++
#include <iostream>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;
template <class T> void setmin(T & a, T const & b) { if (b < a) a = b; }
template <typename T, typename X> auto vectors(T a, X x) { return vector<T>(x, a); }
template <typename T, typename X, typename Y, typename... Zs> auto vectors(T a, X x, Y y, Zs... zs) { auto cont = vectors(a, y, zs...); return vector<decltype(cont)>(x, cont); }
const int inf = 1e9+7;
int main() {
    int h, w; cin >> h >> w;
    vector<vector<int> > xss = vectors(int(), w, h); // column-major
    repeat (y,h) repeat (x,w) {
        char c; cin >> c;
        xss[x][y] = c - 'a';
    }
    int ans = 0;
    repeat (x,w-1) {
        vector<int> const & xs1 = xss[x  ];
        vector<int> const & xs2 = xss[x+1];
        vector<vector<int> > delta = vectors(0, h+1, h+1);
        repeat (y1, h+1) repeat (y, h-y1) delta[y1][0] += xs1[y] == xs2[y1+y];
        repeat (y2, h+1) repeat (y, h-y2) delta[0][y2] += xs1[y2+y] == xs2[y];
        delta[0][0] /= 2;
        repeat (y1, h) repeat (y2, h) delta[y1+1][y2+1] = delta[y1][y2] - (xs1[h-y1-1] == xs2[h-y2-1]);
        vector<vector<int> > dp = vectors(inf, h+1, h+1);
        dp[0][0] = 0;
        repeat (y1, h+1) repeat (y2, h+1) {
            if (y1) setmin(dp[y1][y2], dp[y1-1][y2] + delta[y1-1][y2]);
            if (y2) setmin(dp[y1][y2], dp[y1][y2-1] + delta[y1][y2-1]);
        }
        ans += dp[h][h];
    }
    cout << ans << endl;
    return 0;
}
```
