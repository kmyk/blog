---
layout: post
redirect_from:
  - /writeup/algo/atcoder/code-festival-2016-asapro-1-b/
  - /blog/2016/11/30/code-festival-2016-asapro-1-b/
date: "2016-11-30T13:42:29+09:00"
tags: [ "competitive", "writeup", "atcoder", "codefestival", "suffix-array", "binary-search" ]
"target_url": [ "https://beta.atcoder.jp/contests/cf16-tournament-round1-open/tasks/asaporo_f" ]
---

# CODE FESTIVAL 2016 Elimination Tournament Round 1: B - 数字列をカンマで分ける問題 / Problem where Commas Separate Digits

内部の問題IDが`asaporo_f`なのとても気になる。

## solution

答えを二分探索。判定は貪欲を接尾辞配列で高速に。$O(N \log N)$。

まず、`,`は均等に入れる方がよい。分割後文字列の最大長は$L = \lceil \frac{\|S\|}{K+1} \rceil$未満にはできない。
$S$の長さ$L$の部分文字列$A$を取り、答えがこれより小さいかを貪欲で判定する。
$i$文字目まで使って、部分文字列$[i, i+L)$が$A$以下なら$i \gets i+L$、そうでなければ$i \gets i+L-1$として更新していき、$K+1$回以内に$\S\|$まで見終わればよい。
部分文字列$[i, i+L)$と$A$の比較には接尾辞配列を使うと判定が$O(N)$になる。

二分探索は$N+1$個の部分文字列全ての上でやってよい。
末尾付近の長さが$L$より真に小さい部分文字列はその末尾を`1`で埋めたものより小さく、条件として厳しいため真にならない。
単純な比較だと$L+1$番目以降の文字列が効いてきてしまうが、そのような場合は$L$番目までの部分が一致する部分文字列$A, A'$があり、どちらか大きい方では上手く動く。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <functional>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
using namespace std;

vector<int> suffix_array(string const & s) { // O(N (\log N)^2), sa[i] is the index of i-th smallest substring of s
    int n = s.length();
    vector<int> sa(n+1);
    vector<int> rank(n+1);
    repeat (i,n+1) {
        sa[i] = i;
        rank[i] = i < n ? s[i] : -1;
    }
    auto rankf = [&](int i) { return i <= n ? rank[i] : -1; };
    vector<int> nxt(n+1);
    for (int k = 1; k <= n; k <<= 1) {
        auto cmp = [&](int i, int j) { return make_pair(rank[i], rankf(i + k)) < make_pair(rank[j], rankf(j + k)); };
        sort(sa.begin(), sa.end(), cmp);
        nxt[sa[0]] = 0;
        repeat_from (i,1,n+1) {
            nxt[sa[i]] = nxt[sa[i-1]] + (cmp(sa[i-1], sa[i]) ? 1 : 0);
        }
        rank.swap(nxt);
    }
    return sa;
}

int main() {
    int k; string s; cin >> k >> s;
    vector<int> sa = suffix_array(s);
    vector<int> rank(sa.size()); repeat (i,sa.size()) rank[sa[i]] = i;
    int l = (s.length()+k) / (k+1);
    function<bool (int)> pred = [&](int a) { // monotonic
        int used = 0;
        for (int i = 0; i < s.length(); ++ used) {
            int delta = rank[i] < a ? l : l-1;
            if (delta == 0) return false;
            i += delta;
        }
        return used <= k+1;
    };
    int low = 0, high = rank.size();
    while (low + 1 < high) {
        int mid = (low + high) / 2;
        (pred(mid) ? high : low) = mid;
    }
    int a = low;
    cout << s.substr(sa[a], l) << endl;
    return 0;
}
```
