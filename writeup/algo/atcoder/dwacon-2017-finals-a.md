---
layout: post
alias: "/blog/2017/01/15/dwacon-2017-finals-a/"
date: "2017-01-15T20:00:35+09:00"
tags: [ "competitive", "writeup", "dwacon", "atcoder", "dp" ]
"target_url": [ "https://beta.atcoder.jp/contests/dwacon2017-honsen/tasks/dwango2017final_a" ]
---

# 第3回 ドワンゴからの挑戦状 本選: A - 計算ドリル

## solution

区間DP。
文字を置き換えてもよいという制約の付いた、文脈自由文法の構文解析と認識すればよい。
区間$[l,r)$に対し$k$文字書き換えたときの最大値/最小値を値$\mathrm{dp}\_{\max}(l,r,k), \mathrm{dp}\_{\min}(l,r,k)$とする。
$O({\|S\|}^5)$で通る。
$2$分木になっているのでloopの範囲を丁寧にすれば$O({\|S\|}^4)$に落ちる。

## implementation

``` c++
#include <iostream>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < int(n); ++(i))
using namespace std;
template <class T> void setmax(T & a, T const & b) { if (a < b) a = b; }
template <class T> void setmin(T & a, T const & b) { if (b < a) a = b; }
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }
const int inf = 1e9+7;
int solve(int k, string s) {
    int n = s.length();
    auto dp_max = vectors<int>(n, n+1, k+1, - inf);
    auto dp_min = vectors<int>(n, n+1, k+1, + inf);
    repeat (i,n) if (isdigit(s[i])) {
        dp_max[i][i+1][0] = s[i] - '0';
        dp_min[i][i+1][0] = s[i] - '0';
    }
    repeat (i,n) {
        if (k) {
            dp_max[i][i+1][1] = 9;
            dp_min[i][i+1][1] = 0;
        }
    }
    repeat (len,n+3) repeat (l,n-len+3) {
        int r = l + len;
        if (r <= n+1) {
            repeat_from (m,l+1,r+3) if (m-l >= 1 and r-1-m >= 1 and r-1 < n) {
                repeat (i,k+3) repeat (j,k+3) {
                    if (i+j <= k) {
                        if (s[r-1] == '+') {
                            if (dp_max[l][m][i] != - inf and dp_max[m][r-1][j] != - inf) setmax(dp_max[l][r][i+j], dp_max[l][m][i] + dp_max[m][r-1][j]);
                            if (dp_min[l][m][i] != + inf and dp_min[m][r-1][j] != + inf) setmin(dp_min[l][r][i+j], dp_min[l][m][i] + dp_min[m][r-1][j]);
                        }
                        if (s[r-1] == '-') {
                            if (dp_max[l][m][i] != - inf and dp_min[m][r-1][j] != + inf) setmax(dp_max[l][r][i+j], dp_max[l][m][i] - dp_min[m][r-1][j]);
                            if (dp_min[l][m][i] != + inf and dp_max[m][r-1][j] != - inf) setmin(dp_min[l][r][i+j], dp_min[l][m][i] - dp_max[m][r-1][j]);
                        }
                    }
                    if (i+j+1 <= k) {
                        if (dp_max[l][m][i] != - inf and dp_max[m][r-1][j] != - inf) setmax(dp_max[l][r][i+j+1], dp_max[l][m][i] + dp_max[m][r-1][j]);
                        if (dp_min[l][m][i] != + inf and dp_min[m][r-1][j] != + inf) setmin(dp_min[l][r][i+j+1], dp_min[l][m][i] + dp_min[m][r-1][j]);
                        if (dp_max[l][m][i] != - inf and dp_min[m][r-1][j] != + inf) setmax(dp_max[l][r][i+j+1], dp_max[l][m][i] - dp_min[m][r-1][j]);
                        if (dp_min[l][m][i] != + inf and dp_max[m][r-1][j] != - inf) setmin(dp_min[l][r][i+j+1], dp_min[l][m][i] - dp_max[m][r-1][j]);
                    }
                }
            }
        }
    }
    return dp_max[0][n][k];
}
int main() {
    int k; string s; cin >> k >> s;
    int ans = solve(k, s);
    if (ans == - inf) {
        cout << "NG" << endl;
    } else {
        cout << "OK" << endl;
        cout << ans << endl;
    }
    return 0;
}
```
