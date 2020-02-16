---
layout: post
alias: "/blog/2016/04/10/gcj-2016-qual-d/"
date: 2016-04-10T11:04:32+09:00
tags: [ "competitive", "writeup", "google-code-jam", "gcj", "tree" ]
"target_url": [ "https://code.google.com/codejam/contest/6254486/dashboard#s=p3" ]
---

# Google Code Jam 2016 Qualification Round D. Fractiles

## problem

`L`,`G`からなる長さ$K$の文字列に対し、以下の操作を$C$回行う。

-   文字列中の`L`を最初の長さ$K$の文字列で置き換え、文字列中の`G`を$K$の`G`からなる文字列で置き換える。

こうしてできた文字列があるとする。
その文字列中の高々$S$個の位置の文字(のみ)を(同時に)見て、最初の長さ$K$の文字列に文字`G`が含まれていたかどうか判定したい。
これは可能か、可能ならどうのように$S$個の位置を選べばよいか答えよ。

## solution

Dive a tree. $O(TSC)$.

Think the tree of the replacement.
For example, the original string is `LGL`, the `LGL` is root, another `LGL` is the 1st child of the root, `GGG` is the 2nd, `LGL` is the 3rd, and `LGL` is the 1st child of the 1st child of the root, and so on.
This tree has such a property:
the $i$-th character of last string is `G` if and only if $j$-th children/edges of some nodes are used in the unique path from root to the $i$-th leaf, and $j$-th character of original string is `G`.
So you need to use all of $1, 2, \dots K$-th edges at least once, and it is enough.

## implementation

``` c++
#include <iostream>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;
template <class T> ostream & operator << (ostream & out, vector<T> const & a) { bool i = false; for (T const & it : a) { if (i) out << ' '; else i = true; out << it; } return out; }
void solve() {
    int k, c, s; cin >> k >> c >> s;
    vector<ll> ans;
    int cnt = 0;
    repeat (s_,s) {
        if (cnt >= k) break;
        ll p = 0;
        repeat (i,c) {
            p *= k;
            p += min(k-1, cnt ++);
        }
        ans.push_back(p + 1);
    }
    if (cnt < k) {
        cout << "IMPOSSIBLE" << endl;
    } else {
        cout << ans << endl;
    }
}
int main() {
    int t; cin >> t;
    repeat (i,t) {
        cout << "Case #" << i+1 << ": ";
        solve();
    }
    return 0;
}
```
