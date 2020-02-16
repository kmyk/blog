---
layout: post
alias: "/blog/2018/04/15/srm-733-easy/"
date: "2018-04-15T02:35:07+09:00"
tags: [ "competitive", "writeup", "topcoder", "srm" ]
---

# TopCoder SRM 733 Easy. MinimizeAbsoluteDifferenceDiv1

## solution

${}\_5C4 \cdot 4!$個すべて試して間に合う。$O(1)$。

## note

-   overflowを警戒してPythonで検証コード書いたけど何事もなかった
    -   そのままPythonを提出できればもっと安心なんだけど対応versionすら知らないのでかえって危険かなと思った
-   「unused code多いんだけど」と怒られた。「いや多くないだろ」と言いながら削った。納得がいかない
-   editorial: <https://www.topcoder.com/blog/single-round-match-733-editorials/>

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define ALL(x) begin(x), end(x)
typedef long long ll;
using namespace std;
class MinimizeAbsoluteDifferenceDiv1 { public: vector<int> findTuple(vector<int> x); };

struct rational { int num, den; };
rational make_rational(int num, int den = 1) { return (rational) { num, den }; }
rational operator - (rational a, rational b) { return make_rational(a.num *(ll) b.den - b.num *(ll) a.den, a.den *(ll) b.den); }
bool operator < (rational a, rational b) { return a.num *(ll) b.den < b.num *(ll) a.den; }
bool operator == (rational a, rational b) { return a.num == b.num and a.den == b.den; }

rational get_score(int a, int b, int c, int d) {
    auto r = make_rational(a, b) - make_rational(c, d);
    if (r < make_rational(0)) r = make_rational(0) - r;
    return r;
}
vector<int> MinimizeAbsoluteDifferenceDiv1::findTuple(vector<int> x) {
    vector<int> result;
    rational highscore;
    REP (choose, 5) {
        vector<int> perm;
        REP (i, 5) if (i != choose) {
            perm.push_back(i);
        }
        do {
            rational score = get_score(x[perm[0]], x[perm[1]], x[perm[2]], x[perm[3]]);
            if (result.empty() or score < highscore or (score == highscore and perm < result)) {
                result = perm;
                highscore = score;
            }
        } while (next_permutation(ALL(perm)));
    }
    return result;
}
```
