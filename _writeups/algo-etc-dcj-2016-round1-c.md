---
layout: post
redirect_from:
  - /writeup/algo/etc/dcj-2016-round1-c/
  - /blog/2016/05/30/dcj-2016-round1-c/
date: 2016-05-30T02:57:08+09:00
tags: [ "competitive", "writeup", "dcj", "distributed-code-jam" ]
"target_url": [ "https://code.google.com/codejam/contest/11264486/dashboard#s=p2" ]
---

# Google Code Jam 2016 Distributed Round 1 C. rps

## problem

$2^N$人の人間が居て、トーナメント式のじゃんけん大会をする。
それぞれの人間は同じ手を出し続け、その出す手は分かっている。
引き分けが続く場合はIDが小さい方を勝者とする。
対戦の配置が与えられるので、その勝者を答えよ。

## solution

Compute it simply, using all nodes.

Let nodes have the range of the assigned items, and give/take the border items.
The nodes sometimes become something sparse, there are empty nodes between non-empty nodes, so you have to bring the border items recursively.

## implementation

``` c++
#include <message.h>
#include "rps.h"

#include <iostream>
#include <deque>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;

pair<int,char> battle(pair<int,char> a, pair<int,char> b) {
    if (a.second == b.second
            or a.second == 'R' and b.second == 'S'
            or a.second == 'P' and b.second == 'R'
            or a.second == 'S' and b.second == 'P') {
        return a;
    } else {
        return b;
    }
}

int main() {
    int nodes = NumberOfNodes();
    int my_id = MyNodeId();
    int n = GetN();
    if ((1ll<<n) <= nodes) {
        nodes = 1ll<<n;
        if (nodes <= my_id) return 0;
    }

    int l = (1ll<<n) * my_id / nodes;
    int r = (1ll<<n) * (my_id + 1) / nodes;
    deque<pair<int,char> > players;
    for (int i = l; i < r; ++ i) {
        players.push_back(make_pair(i, GetFavoriteMove(i)));
    }

    repeat (round,n) {
        if (my_id + 1 < nodes) {
            Receive(my_id + 1);
            while (true) {
                char cmd = GetChar(my_id + 1);
                if (cmd == 'Q') break;
                if (cmd == '<') {
                    int  i = GetInt( my_id + 1);
                    char c = GetChar(my_id + 1);
                    players.push_back(make_pair(i, c));
                    ++ r;
                }
            }
        }
        if (my_id) {
            if ((r - l) % 2 != 0) {
                PutChar(my_id - 1, '<');
                PutInt( my_id - 1, players.front().first);
                PutChar(my_id - 1, players.front().second);
                players.pop_front();
                ++ l;
            }
            PutChar(my_id - 1, 'Q');
            Send(my_id - 1);
        }
        assert ((r - l) % 2 == 0);
        deque<pair<int,char> > next_players;
        for (int i = l; i < r; i += 2) {
            next_players.push_back(battle(players[i-l], players[i-l+1]));
        }
        players = next_players;
        l /= 2;
        r /= 2;
    }

    if (my_id == 0) {
        assert (players.size() == 1);
        cout << players.front().first << endl;
    } else {
        assert (players.size() == 0);
    }
    return 0;
}
```
