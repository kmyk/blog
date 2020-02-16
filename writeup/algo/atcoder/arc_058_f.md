---
layout: post
date: 2018-08-23T05:01:07+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "dp", "string", "lie", "optimization" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc058/tasks/arc058_d" ]
redirect_from:
  - /writeup/algo/atcoder/arc-058-f/
---

# F - 文字列大好きいろはちゃん / Iroha Loves Strings

## solution

愚直なDPを考え、そのDP表の内で真に必要な部分以外は埋めないことにする。
その上でよく観察すると、DP表中の文字列はすべて同一の文字列のprefixになっていることが分かる。
このことを用いて適切に実装すると真に計算量が落ちる。
いくらか手を抜いて実装をすると計算量は $$O(K \sum |s_i|)$$。

愚直DPは$i$番目の文字列まで使ってちょうど長さ$j$にしたときの辞書順最小の文字列を$$\mathrm{dp}(i, j)$$とするもの。
そのまま実装すると時間計算量は$$O(K \sum |s_i|)$$で、空間計算量は$$O(NK^2)$$あるいは$$O(K^2)$$。
表の必要なところのみ埋めるとする。
まず、それ以降に文字列を繋げて長さをちょうど$K$にできないような位置については埋めない。
すると表中の同じ行のふたつの値$$t_1 = \mathrm{dp}(i, j_1), t_2 = \mathrm{dp}(i, j_2)$$を取り出したときに常に一方が一方のprefixになっているようにできる。
そうなっていないと仮定し、一般性を失わず$t_1 \lt t_2$とすると、$t_1$の後ろに文字列を繋げて長さをちょうど$K$にできるのだから$t_2$は無視してよいことが分かる。
このようなとき$$t = \max_j \mathrm{dp}(i, j)$$を考えれば、表中の同じ行のすべての文字列はこの$t$のprefixになっている。
よってこの共通文字列$t$と長さいくつのprefixが存在しているかの表を持てば状態は十分。
この形に合わせて適切に実装すると(おそらくはテストケースが弱いために)間に合う。
高速化のポイントは `vector` への一様代入に `fill` や `vector:assign` を使わず $O(1)$ でやること。

## note

-   editorialを見た。言われれば分かる範囲の解法であるが思い付ける気がしない。
-   実装の手を抜いたため。その結果として文字が$1$種類のみの場合がつらく、手元で生成したランダムケースで試すと$13$秒ほどかかっている。
    AtCoder上にも `allsame0` `allsame_ex0` というケースが存在しているのでこれでTLEするはずだが、どちらも$500$ms以内に停止してACしてしまう。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define REP_R(i, n) for (int i = int(n) - 1; (i) >= 0; -- (i))
using namespace std;
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

string solve(int n, int k, vector<string> const & s) {
    auto required = vectors(n + 1, k + 1, false);
    required[n][k] = true;
    REP_R (i, n) {
        int len = s[i].length();
        REP (j, k + 1) if (required[i + 1][j]) {
            required[i][j] = true;
            if (j - len >= 0) {
                required[i][j - len] = true;
            }
        }
    }

    string t;
    vector<int> cur(k + 1, -1), prv;
    cur[0] = 0;
    REP (i, n) {
        int len = s[i].length();
        cur.swap(prv);
        cur.assign(k + 1, -1);

        int modified = INT_MAX;
        int clear = INT_MAX;
        REP_R (j, k + 1) if (required[i + 1][j]) {
            if (j - len >= 0 and prv[j - len] != -1) {
                int l = j - len, r = t.length();

                if (len <= r - l and t.compare(l, len, s[i]) == 0) {  // if s[i] is a prefix of t[l, r)
                    cur[j] = j;

                } else if (r - l < len and t.compare(l, r - l, s[i], 0, r - l) == 0) {  // if t[l, r) is a prefix of s[i]
                    t += s[i].substr(r - l);
                    cur[j] = j;

                } else if (s[i].compare(0, len, t, l, r - l) < 0) {  // if you should truly replace t[l, r) with s[i]
                    for (int j1 = j - len, j2 = 0; j1 < t.length() and j2 < len; ++ j1, ++ j2) {
                        if (t[j1] != s[i][j2]) {
                            modified = j1;
                            break;
                        }
                    }
                    clear = j;
                    cur[j] = j;
                    t.erase(t.begin() + j - len, t.end());
                    t += s[i];
                }

            }
            if (prv[j] != -1 and j <= modified) {
                cur[j] = j;
            }
        }

        // execute clearing
        REP (j, k + 1) {
            if (cur[j] > clear) {
                cur[j] = -1;
            }
        }
    }
    assert (t.length() == k);
    return t;
}

int main() {
    int n, k; cin >> n >> k;
    vector<string> s(n);
    REP (i, n) cin >> s[i];
    cout << solve(n, k, s) << endl;
    return 0;
}
```
