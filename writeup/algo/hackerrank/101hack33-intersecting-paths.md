---
layout: post
redirect_from:
  - /blog/2016/01/21/hackerrank-101hack33-intersecting-paths/
date: 2016-01-21T22:22:54+09:00
tags: [ "competitive", "writeup", "hackerrank", "dp", "stack", "doubling" ]
---

# Hackerrank 101 Hack Jan 2016 Intersecting Paths

editorialを見た。これはまだ解くには厳しい。

## [Intersecting Paths](https://www.hackerrank.com/contests/101hack33/challenges/intersecting-paths)

### 解法

以下が成り立つのでdoublingする。
$x,y$のpathが交差 $\Leftrightarrow$ $x,y$のpathの終端が同じあるいは$x$のpathが$y$を通る。

"target_url": [ "small" ]
---

# Hackerrank 101 Hack Jan 2016 Intersecting Paths
成り立つことの証明(editorialにある)はちゃんと追えていない。
</small>

### 実装

``` c++
#include <iostream>
#include <vector>
#include <stack>
#include <cmath>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_reverse(i,n) for (int i = (n)-1; (i) >= 0; --(i))
using namespace std;
int main() {
    // input
    int n; cin >> n;
    vector<int> a(n); repeat (i,n) cin >> a[i];
    // make single step graph
    vector<int> up(n, -1); {
        stack<int> stk;
        repeat (i,n) {
            while (not stk.empty() and a[stk.top()] < a[i]) {
                int j = stk.top(); stk.pop();
                up[j] = i;
            }
            stk.push(i);
        }
    }
    vector<int> down(n, -1); {
        stack<int> stk;
        repeat (i,n) {
            while (not stk.empty() and a[stk.top()] > a[i]) {
                int j = stk.top(); stk.pop();
                down[j] = i;
            }
            stk.push(i);
        }
    }
    // make table for doubling
    int log_n = log2(n);
    vector<vector<int> > skip(log_n, vector<int>(n, -1));
    repeat (i,n) if (down[i] != -1) skip[0][i] = up[down[i]];
    repeat (k,log_n-1) {
        repeat (i,n) if (skip[k][i] != -1) {
            skip[k+1][i] = skip[k][skip[k][i]];
        }
    }
    // make table of last place
    vector<int> end(n, -1);
    repeat_reverse (i,n) {
        end[i] = i;
        repeat_reverse (k,log_n) {
            if (skip[k][i] != -1) {
                end[i] = end[skip[k][i]];
                break;
            }
        }
    }
    repeat (i,n) {
        if (down[end[i]] != -1) {
            end[i] = down[end[i]];
        }
    }
    // output
    int q; cin >> q;
    repeat (i,q) {
        int x, y; cin >> x >> y; -- x; -- y;
        bool ans = false;
        if (end[x] == end[y]) {
            ans = true;
        } else {
            // doubling
            int z = x;
            repeat_reverse (k,log_n) {
                int nz = skip[k][z];
                if (nz != -1 and nz <= y) z = nz;
            }
            int nz = down[z];
            if (nz != -1 and nz <= y) z = nz;
            if (z == y) ans = true;
        }
        cout << ans << endl;
    }
    return 0;
}
```
