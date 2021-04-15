---
layout: post
redirect_from:
  - /writeup/algo/etc/dcj-2016-round1-b/
  - /blog/2016/05/30/dcj-2016-round1-b/
date: 2016-05-30T02:57:03+09:00
tags: [ "competitive", "writeup", "dcj", "distributed-code-jam" ]
"target_url": [ "https://code.google.com/codejam/contest/11264486/dashboard#s=p1" ]
---

# Google Code Jam 2016 Distributed Round 1 B. oops

I've got MLE.
So I couldn't advance the round 2. If there was a practice round or I joined the last year's one, I could...

## problem

愚直解のコードが与えられている。
これと等価な処理を高速に実行せよ。

## solution

Compute the maximum of the difference of items.

Distribute the ranges into the nodes, calculate max and min in each node, and solve in the master node. $O(N / P)$ where $P$ is the number of nodes.

## memo

### limits

-   The memory limit is often very small.
-   The `Send`/`Receive` limit is a bit large.

### how to test

`-Wall`,`-D_GLIBCXX_DEBUG` is important.

``` sh
$ ../dcj-testing-tool/dcj.sh build --source=a.cpp --extra_flags=-Wall,-D_GLIBCXX_DEBUG
$ ../dcj-testing-tool/dcj.sh run --executable=./a --nodes=100 --output=all
```

### header, sample

``` sh
$ ls *.h
oops.1.h  oops.2.h  oops.3.h  oops.h
$ cat oops.h
#include "oops.1.h"
```

### distribute items into nodes

``` c++
int l = n *(ll) my_id / nodes;
int r = n *(ll) (my_id + 1) / nodes;
repeat_from (i,l,r) { ... }
```

or

``` c++
for (int i = my_id; i < n; i += nodes) { ... }
```

### nodes whose range is empty

``` c++
if (n <= nodes) {
    nodes = n;
    if (nodes <= my_id) return 0;
}
```

## implementation

If you use `vector<int>` ans `sort( ... )`, it causes RE (I think this RE is MLE with `std::bad_alloc`).

``` c++
#include <message.h>
#include "oops.h"
#define MASTER_NODE 0

#include <iostream>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
typedef long long ll;
using namespace std;
template <class T> bool setmax(T & l, T const & r) { if (not (l < r)) return false; l = r; return true; }
template <class T> bool setmin(T & l, T const & r) { if (not (r < l)) return false; l = r; return true; }

int main() {
    ll nodes = NumberOfNodes();
    ll my_id = MyNodeId();
    ll n = GetN();

    ll l = n * my_id / nodes;
    ll r = n * (my_id + 1) / nodes;
    ll max_x = GetNumber(0);
    ll min_x = GetNumber(0);
    repeat_from (i,l,r) {
        ll x = GetNumber(i);
        setmax(max_x, x);
        setmin(min_x, x);
    }
    PutLL(MASTER_NODE, max_x);
    PutLL(MASTER_NODE, min_x);
    Send(MASTER_NODE);

    if (my_id == MASTER_NODE) {
        repeat (node,nodes) {
            Receive(node);
            setmax(max_x, GetLL(node));
            setmin(min_x, GetLL(node));
        }
        cout << max_x - min_x << endl;
    }
    return 0;
}
```
