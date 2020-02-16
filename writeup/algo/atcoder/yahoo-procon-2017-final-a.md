---
layout: post
redirect_from:
  - /blog/2017/03/26/yahoo-procon-2017-final-a/
date: "2017-03-26T11:26:35+09:00"
tags: [ "competitive", "writeup", "atcoder", "yahoo-procon", "dp", "edit-distance" ]
"target_url": [ "https://beta.atcoder.jp/contests/yahoo-procon2017-final-open/tasks/yahoo_procon2017_final_a" ]
---

# 「みんなのプロコン」本選: A - YahooYahooYahoo

## solution

DP。$O(N)$。

編集距離を求めるのだが編集先を複数から選べる。
`yahoo`を作ればよいのでそのどこまで埋めたかを引数に持って、$\mathrm{dp} : (N+1) \times \\{ \mathrm{y}, \mathrm{ya}, \mathrm{yah}, \mathrm{yaho}, \mathrm{yahoo} \\} \to \mathbb{N}$みたいにすればよい。

更新の際には注意があって、`yahoo`上を動くloopは$2$周ぐらい必要。挿入後に元の文字列の文字を使ってまた挿入するパターンがあるため。

## implementation

``` c++
#include <iostream>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
using namespace std;
template <class T> inline void setmin(T & a, T const & b) { a = min(a, b); }
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }
const int inf = 1e9+7;
int main() {
    string s; cin >> s;
    int n = s.length();
    auto dp = vectors(5, n+1, inf);
    dp[0][0] = 0;
    repeat (i,n) {
        repeat (j,11) {
            if ((s[i] == 'y' and j%5 == 0)
                    or (s[i] == 'a' and j%5 == 1)
                    or (s[i] == 'h' and j%5 == 2)
                    or (s[i] == 'o' and (j%5 == 3 or j%5 == 4))) {
                setmin(dp[(j+1)%5][i+1], dp[j%5][i]);
            }
            setmin(dp[(j+1)%5][i+1], dp[j%5][i] + 1); // replace
            setmin(dp[j%5][i+1],     dp[j%5][i] + 1); // delete
            setmin(dp[(j+1)%5][i+1], dp[j%5][i+1] + 1); // insert
        }
    }
    cout << dp[0][n] << endl;
    return 0;
}
```
