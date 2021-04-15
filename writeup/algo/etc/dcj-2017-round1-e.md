---
layout: post
redirect_from:
  - /writeup/algo/etc/dcj-2017-round1-e/
  - /blog/2017/05/15/dcj-2017-round1-e/
date: "2017-05-15T11:08:49+09:00"
tags: [ "competitive", "writeup", "dcj", "distributed-code-jam" ]
"target_url": [ "https://code.google.com/codejam/contest/8314486/dashboard#s=p4" ]
---

# Google Code Jam Distributed Round 1 2017: E. query_of_death

全完$45$位という大勝利だった。

## solution

各ノードに区間を割り当て左から順に(単純に)舐め、その後壊れているか確認をする。
壊れたノードの担当していた区間を壊れていない残りのノードに再度分配し、これをそれぞれ右から舐める。
区間長は$\frac{1}{K}$になっているので、今回は各点ごとに確認をする。
悪いクエリの位置$i\_{\mathrm{qod}}$が分かるので、これをまとめ上げれば答え。
長さ$N$と確認の回数$c$とノード数$K$に対し$O(\frac{N + c}{K} + K + \frac{Nc}{K^2})$。

今回は$2$段で止めたが最後まで再帰でやるのもよいかもしれない。

## implementation

$K = 100$で$N \le 10^8$。確認回数$c = 100$は多すぎるかなと思ったが$478$msなので余裕はあったらしい。なお制限時間は$2$sec。

``` c++
#include "message.h"
#include "query_of_death.h"
#include <cstdio>
#include <vector>
#include <algorithm>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_reverse(i,n) for (int i = (n)-1; (i) >= 0; --(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using ll = long long;
using namespace std;

int main() {
    const int root_node_id = 0;
    const int number_of_nodes = NumberOfNodes();
    const int my_node_id = MyNodeId();
    int n = GetLength();
    vector<bool> value;
    { // on each node
        int l = (n *(ll)  my_node_id     ) / number_of_nodes;
        int r = (n *(ll) (my_node_id + 1)) / number_of_nodes;
        value.resize(r-l);
        repeat (i,r-l) {
            value[i] = GetValue(l+i);
        }
        bool is_broken = false;
        if (not value.empty()) {
            repeat (iteration, 100) {
                if (GetValue(l) != value[0]) {
                    is_broken = true;
                }
            }
        }
        int message = whole(count, value, true);
        if (is_broken) message = -1;
        PutInt(root_node_id, message);
        Send(root_node_id);
    }
    if (my_node_id == root_node_id) { // sum up
        int sum = 0;
        int broken_node_id = -1;
        repeat (node_id, number_of_nodes) {
            Receive(node_id);
            int message = GetInt(node_id);
            if (message == -1) {
                broken_node_id = node_id;
            } else {
                sum += message;
            }
        }
        repeat (node_id, number_of_nodes) {
            PutInt(node_id, broken_node_id);
            Send(node_id);
        }
        PutInt(broken_node_id, sum);
        Send(broken_node_id);
    }
    // on each node
    Receive(root_node_id);
    int broken_node_id = GetInt(root_node_id);
    int broken_l = (n *(ll)  broken_node_id     ) / number_of_nodes;
    int broken_r = (n *(ll) (broken_node_id + 1)) / number_of_nodes;
    if (my_node_id != broken_node_id) {
        int updated_node_id = my_node_id - (broken_node_id < my_node_id);
        int l = broken_l + ((broken_r - broken_l) *(ll)  updated_node_id     ) / (number_of_nodes - 1);
        int r = broken_l + ((broken_r - broken_l) *(ll) (updated_node_id + 1)) / (number_of_nodes - 1);
        int qod = -1;
        value.clear();
        value.resize(r-l);
        repeat_reverse (i,r-l) {
            value[i] = GetValue(l+i);
            repeat (iteration, 100) {
                if (GetValue(l+i) != value[i]) {
                    qod = l+i;
                    value[i] = false;
                    break;
                }
            }
            if (qod != -1) break;
        }
        int message = whole(count, value, true);
        PutInt(broken_node_id, message);
        PutInt(broken_node_id, qod);
        Send(broken_node_id);
    } else {
        Receive(root_node_id);
        int sum = GetInt(root_node_id);
        repeat_reverse (node_id, number_of_nodes) if (node_id != broken_node_id) {
            Receive(node_id);
            int message = GetInt(node_id);
            int qod = GetInt(node_id);
            sum += message;
            if (qod != -1) {
                sum += count(value.begin(), value.begin() + (qod - broken_l + 1), true);
                break;
            }
        }
        printf("%d\n", sum);
    }
    return 0;
}
```
