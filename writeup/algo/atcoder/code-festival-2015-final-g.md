---
layout: post
alias: "/blog/2015/11/26/code-festival-2015-final-g/"
date: 2015-11-26T23:03:14+09:00
tags: [ "competitive", "writeup", "codefestival", "graph", "dfs", "interval", "dp", "tree", "forest", "rooted-tree" ]
---

# CODE FESTIVAL 2015 決勝 G - スタンプラリー

本番は難しそうに感じたので手を付けなかった。

<!-- more -->

## [G - スタンプラリー](https://beta.atcoder.jp/contests/code-festival-2015-final-open/tasks/codefestival_2015_final_g) {#g}

### 反省

golfで遊んでいてほとんど聞いていなかった解説で、「区間」「dp」などと言っていたのを元に、とりあえず$O(n^4)$の解を書こうとしたらバグらせてとても苦労した。書き上げて、ちょっと考えたら$O(n^3)$に落とせる感じが強いなあと感じたが、疲れたので解説を見た。解説のslideに載っている漸化式をそのまま翻訳すれば書けてしまったので、達成感すら得られなかった。解説の安易な閲覧はすべきではなかった。

### 解説

区間dp。特に、dpはtableを2つ持って同時に更新していく。

chokudaiさんによる[解説slide](http://www.slideshare.net/chokudai/code-festival-2015-final)が分かりやすい。

### 実装

``` c++
#include <iostream>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
typedef long long ll;
using namespace std;
constexpr ll mod = 1000000007;
int main() {
    int n; cin >> n;
    vector<int> c(n); repeat (i,n) { cin >> c[i]; -- c[i]; }
    if (c[0] != 0) {
        cout << 0 << endl;
        return 0;
    }
    vector<vector<ll> >   tree(n+1, vector<ll>(n+1)); // [l, r)
    vector<vector<ll> > forest(n+1, vector<ll>(n+1)); // [l, r)
    repeat (i,n) {
          tree[i][i+1] = 1;
        forest[i][i+1] = 1;
    }
    repeat_from (len,2,n+1) repeat (l,n+1) {
        int r = l + len;
        if (n+1 <= r) break;
        tree[l][r] = forest[l+1][r];
        forest[l][r] = tree[l][r];
        repeat_from (k,l+1,r+1) {
            if (k == r or c[l] < c[k]) {
                forest[l][r] += tree[l][k] * forest[k][r] % mod;
                forest[l][r] %= mod;
            }
        }
    }
    cout << tree[0][n] << endl;
    return 0;
}
```
