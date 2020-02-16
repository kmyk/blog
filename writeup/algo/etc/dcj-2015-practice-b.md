---
layout: post
alias: "/blog/2017/05/12/dcj-2015-practice-b/"
date: "2017-05-12T22:26:01+09:00"
tags: [ "competitive", "writeup", "dcj", "distributed-code-jam", "mle" ]
"target_url": [ "https://codejam.withgoogle.com/codejam/contest/4264486/dashboard#s=p1" ]
---

# Google Code Jam Distributed Practice Round 2015: B. sandwich

DCJ通過者へメールでURLが送られてくるPractice Roundにて。
MLEを踏んだので本番のためにまとめておいた。

## problem

長さ$N \le 5 \times 10^8$の数列$a$がある。
この数列の先頭と末尾からそれぞれ$l, r$項を重ならない(つまり$l + r \le N$)ように取り出したときの、その和$\sum\_{i \lt l} a\_i + sum\_{N-r \le i} a\_i$の最大値を答えよ。

## solution

区間に分割してそれぞれで総和等を計算し、最後にまとめる。node数を$k$として$O(N/k + k)$。

## MLEについて

MLEには注意。Limitsの欄より、この問題では

>   Each node will have access to 128MB of RAM, and a time limit of 3 seconds.

である。

Large inputの制約では$N = 5 \times 10^8$かつnode数$k = 100$である。
$N$を均等に分配すると$\frac{N}{k} = 5 \times 10^6$。
`long long`は今回$8$byteなので、`vector<long long>(N/k)`とすると$4 \times 10^7$byteが消える。
$128$MBは$1.28 \times 10^8$byteであるので、これを$3$本持とうとすると$1.2 \times 10^8$byteとなりMLEとなる。

このMLEはSmall inputでは再現しないことにも注意したい。
また、Practice Round/View my submissionsにおいてはRuntime Errorとして通知された。

## implementation

``` c++
#include "message.h"
#include "sandwich.h"
#include <cstdio>
#include <vector>
#include <numeric>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_reverse(i,n) for (int i = (n)-1; (i) >= 0; --(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using ll = long long;
using namespace std;
template <class T> inline void setmax(T & a, T const & b) { a = max(a, b); }

int main() {
    const int number_of_nodes = NumberOfNodes();
    const int my_node_id = MyNodeId();
    int n = GetN();
    { // on each node
        int l = (n *(ll)  my_node_id     ) / number_of_nodes;
        int r = (n *(ll) (my_node_id + 1)) / number_of_nodes;
        vector<ll> acc(r - l + 1);
        repeat (i, r - l) {
            acc[i+1] = acc[i] + GetTaste(l + i);
        }
        vector<ll> right_max(r - l + 1); // [i, r - l)
        repeat_reverse (i, r - l) {
            right_max[i] = max(right_max[i+1], acc[r-l] - acc[i]);
        }
        ll left_max = 0; // [0, i)
        ll both_max = 0;
        repeat (i, r - l + 1) {
            setmax(left_max, acc[i] - acc[0]);
            setmax(both_max, left_max + right_max[i]);
        }
        PutLL(0, acc[r-l] - acc[0]);
        PutLL(0, left_max);
        PutLL(0, right_max[0]);
        PutLL(0, both_max);
        Send(0);
    }
    if (my_node_id == 0) { // sum up
        vector<ll> total(number_of_nodes);
        vector<ll> left_max(number_of_nodes);
        vector<ll> right_max(number_of_nodes);
        vector<ll> both_max(number_of_nodes);
        repeat (node_id, number_of_nodes) {
            Receive(node_id);
            total[node_id] = GetLL(node_id);
            left_max[node_id] = GetLL(node_id);
            right_max[node_id] = GetLL(node_id);
            both_max[node_id] = GetLL(node_id);
        }
        ll total_of_total = whole(accumulate, total, 0ll);
        vector<ll> left_acc_max(number_of_nodes + 1); { // [0, i)
            ll acc = 0;
            repeat (i, number_of_nodes) {
                left_acc_max[i+1] = max(left_acc_max[i], acc + left_max[i]);
                acc += total[i];
            }
        }
        vector<ll> right_acc_max(number_of_nodes + 1); { // [i, number_of_nodes)
            ll acc = 0;
            repeat_reverse (i, number_of_nodes) {
                right_acc_max[i] = max(right_acc_max[i+1], acc + right_max[i]);
                acc += total[i];
            }
        }
        ll result = 0;
        setmax(result, total_of_total);
        repeat (i, number_of_nodes) {
            setmax(result, total_of_total - total[i] + both_max[i]);
        }
        repeat (i, number_of_nodes + 1) {
            setmax(result, left_acc_max[i] + right_acc_max[i]);
        }
        printf("%lld\n", result);
    }
    return 0;
}
```
