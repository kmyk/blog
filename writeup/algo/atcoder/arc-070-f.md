---
layout: post
alias: "/blog/2017/04/04/arc-070-f/"
date: "2017-04-04T10:54:47+09:00"
title: "AtCoder Regular Contest 070: F - HonestOrUnkind"
tags: [ "competitive", "writeup", "atcoder", "arc", "reactive", "propositional-logic" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc070/tasks/arc070_d" ]
---

## solution

$2B$回ぐらい使って長さ$B+1$の含意のpathを作って正直者ひとりを確定し、残りはすべてこの人に聞く。時間計算量$O(A + B)$。

$A \le B$の場合は明らかに`Impossible`。不親切な人全員が一貫して嘘を付けば正直者と区別できない。
正直者がひとりでも判明すれば、後は$N-1$回その人に聞けば終わりである。
つまり$N+1$回以内で正直者をひとり見付ければよい。

人$i$が正直であることを$\phi(i)$と書くとする。
人$i$に人$j$が親切かどうか尋ねると、$(\phi(i) \to \phi(j)) \oplus (\phi(i) \to \lnot \phi(j))$のどちらかが得られる。
これを使って$\phi(i_0) \to \phi(i_1) \to \dots \to \phi(i_B)$という互いに異なる人による長さ$B+1$の鎖が得られれば、不親切は高々$B$人なので正直者が含まれておりまた真であることが推移することから$\phi(i_B)$は真である。
$i_0 = 0$から始めて構築していく。$\phi(i) \to \lnot \phi(j)$が得られた場合が問題であるが、この場合$i, j$をまとめて鎖から除いてしまう。
$\phi(i) \land \phi(j)$は偽なので必ず$B$がdecrementされるのでこれは高々$B$回発生する。
発生により目標の鎖の長さは$1$縮めてよいことと、($i$を鎖に入れるためのクエリが無駄になるとしても)$B \lt A$なので$2B \lt N$より問題にはならない。

## implementation

``` c++
#include <cstdio>
#include <vector>
#include <stack>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
using namespace std;

int main() {
    int a, b; scanf("%d%d", &a, &b);
    if (a <= b) {
        printf("Impossible\n");
    } else {
        auto query = [](int i, int j) {
            printf("? %d %d\n", i, j);
            fflush(stdout);
            char c; scanf(" %c", &c);
            switch (c) {
                case 'Y': return true;
                case 'N': return false;
                default: assert (false);
            }
        };
        // find an honest man
        stack<int> chain;
        repeat (i, a + b) {
            if (chain.empty()) {
                chain.push(i);
            } else {
                if (query(chain.top(), i)) {
                    chain.push(i);
                } else {
                    chain.pop();
                }
            }
        }
        // ask him
        assert (not chain.empty());
        int honest = chain.top();
        vector<bool> result(a + b);
        repeat (i, a + b) {
            result[i] = query(honest, i);
        }
        // output
        printf("! ");
        repeat (i, a + b) printf("%d", int(result[i]));
        printf("\n");
    }
    return 0;
}
```
