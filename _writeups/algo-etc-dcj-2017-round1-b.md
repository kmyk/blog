---
layout: post
redirect_from:
  - /writeup/algo/etc/dcj-2017-round1-b/
  - /blog/2017/05/15/dcj-2017-round1-b/
date: "2017-05-15T11:08:44+09:00"
tags: [ "competitive", "writeup", "dcj", "distributed-code-jam" ]
"target_url": [ "https://code.google.com/codejam/contest/8314486/dashboard#s=p1" ]
---

# Google Code Jam Distributed Round 1 2017: B. pancakes

sampleを切り替えるのはsymbolic linkの貼り替えでしてたけど、もうちょっといい方法ないだろうか。

## solution

revolutionで区切ると面倒なので移動で区切る。
各ノードに$[0, N)$の区間を分配し、区間$[l, r)$を担当するノードは$\mathrm{Item}\_{l-1}$から$\mathrm{Item}\_{r}$へ全て配り終えた後に移動するときの距離を計算するようにする。
$\mathrm{Item}\_0 = 0, \; \mathrm{Item}\_N = D-1$としておいて、全て足して$1$加えて$D$で割れば答え。
stack size $N$とノード数$K$に対し$O(\frac{N}{K} + K)$。

## implementation

$K = 100$で$N \le 10^8$なのに$759$msなのは、`GetStackItem(i)`の$0.8$usにより$800$ms固定で乗るからだろう。
むしろこれより速いのはなぜなのか。

``` c++
#include "message.h"
#include "pancakes.h"
#include <cstdio>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < int(n); ++(i))
using ll = long long;
using namespace std;

int main() {
    const int number_of_nodes = NumberOfNodes();
    const int my_node_id = MyNodeId();
    int n = GetStackSize();
    int d = GetNumDiners();
    { // on each node
        int l = ((n+1) *(ll)  my_node_id     ) / number_of_nodes;
        int r = ((n+1) *(ll) (my_node_id + 1)) / number_of_nodes;
        ll acc = 0;
        int cur = (l == 0 ? 0 : GetStackItem(l-1));
        repeat_from (i,l,r) {
            int nxt = i == n ? d-1 : GetStackItem(i);
            if (cur <= nxt) {
                acc += nxt - cur;
                cur = nxt;
            } else {
                acc += d + nxt - cur;
                cur = nxt;
            }
        }
        PutLL(0, acc);
        Send(0);
    }
    if (my_node_id == 0) { // sum up
        ll acc = 0;
        repeat (node_id, number_of_nodes) {
            Receive(node_id);
            acc += GetLL(node_id);
        }
        assert ((acc + 1) % d == 0);
        ll result = (acc + 1) / d;
        printf("%lld\n", result);
    }
    return 0;
}
```
