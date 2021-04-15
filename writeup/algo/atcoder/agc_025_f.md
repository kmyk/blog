---
layout: post
date: 2018-09-07T23:48:01+09:00
tags: [ "competitive", "writeup", "atcoder", "agc" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc025/tasks/agc025_f" ]
redirect_from:
  - /writeup/algo/atcoder/agc_025_f/
  - /writeup/algo/atcoder/agc-025-f/
---

# AtCoder Grand Contest 025: F - Addition and Andition

## 解法

よくない形になってるところを解消して回るやつ。
MSBからそれぞれ処理していき上に伝播させていく。
$0, 1$だけでなく$2$も許すと実装が楽。
$O(N + M + K)$。

問題で指示されているのは「次を$K$回やれ: bit積 $Z = X \And Y$ とおいて加算 $X \gets X + Z$ と $Y \gets Y + Z$ で更新する」。
愚直にやると定数倍が小さいとはいえ $O(KN)$。
いくつか観察をしよう。
まずbit積の性質から $X_i = Y_i = 1$ であるような位置$i$にのみ注目すればよいことが分かる。
さらにそのような位置から影響は上側に伝播していく。
他の $j \gt i$ を見たとき $X_j = Y_j = 0$ なら気にしなくてよい。
$X_j = Y_j = 1$ なら $j$ についても同様に等速で伝播が発生するので $X_j = Y_j = 0$ と同じとみなせる。
一方 $X_j \ne Y_j$ なら問題で、繰り上がりの処理が発生する。

ここまでにより位置$i$を上からやっていくとよさそうという気持ちになる。
ここである種の転置も隠れていることに注意。
つまり「すべての位置$i$について処理することを$K$回やる」のでなくて「位置$i$を上から順に見て順番に$K$回処理する」。
計算量が不安ではあるがいけそうな気がするので実装すると通る。
たぶん証明もできるがそこそこ手間そう。

## メモ

-   体感$900$点 (解けたので)
-   いつもこういうのカット除去ぽいなあってなりながら解いてる

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define REP_R(i, n) for (int i = int(n) - 1; (i) >= 0; -- (i))
#define ALL(x) begin(x), end(x)
using namespace std;

pair<string, string> solve(int n, int m, int k, string s, string t) {
    reverse(ALL(s));
    reverse(ALL(t));
    REP (i, m + k + 100) s.push_back('0');
    REP (j, n + k + 100) t.push_back('0');

    stack<int> stk;
    function<void (int, int)> go = [&](int i, int k1) {
        assert (k1 >= 0);
        if (not stk.empty()) {
            assert (stk.top() >= i);
            if (stk.top() == i) stk.pop();
        }

        if (s[i] == '1' and t[i] == '1') {
            if (k1 == 0) {
                // nop
            } else {
                s[i] = '0';
                t[i] = '0';
                int j = stk.empty() ? INT_MAX : stk.top();
                if (k1 < j - i) {
                    assert (s[i + k1] == '0');
                    assert (t[i + k1] == '0');
                    s[i + k1] = '1';
                    t[i + k1] = '1';
                } else {
                    stk.pop();
                    s[j] += 1;
                    t[j] += 1;
                    go(j, k1 - (j - i));
                }
            }

        } else if (s[i] == '1' and t[i] == '0') {
            stk.push(i);

        } else if (s[i] == '0' and t[i] == '1') {
            stk.push(i);

        } else if (s[i] == '0' and t[i] == '0') {
            // nop

        } else if (s[i] == '2' and (t[i] == '0' or t[i] == '1')) {
            s[i] = '0';
            s[i + 1] += 1;
            go(i + 1, k1);
            if (t[i] == '1') stk.push(i);

        } else if ((s[i] == '0' or s[i] == '1') and t[i] == '2') {
            t[i] = '0';
            t[i + 1] += 1;
            go(i + 1, k1);
            if (s[i] == '1') stk.push(i);

        } else {
            assert (false);
        }
    };
    REP_R (i, n + m) {
        go(i, k);
    }

    while (s.back() == '0') s.pop_back();
    while (t.back() == '0') t.pop_back();
    reverse(ALL(s));
    reverse(ALL(t));
    return make_pair(s, t);
}

int main() {
    int n, m, k; cin >> n >> m >> k;
    string s; cin >> s;
    string t; cin >> t;
    tie(s, t) = solve(n, m, k, s, t);
    cout << s << endl;
    cout << t << endl;
    return 0;
}
```
