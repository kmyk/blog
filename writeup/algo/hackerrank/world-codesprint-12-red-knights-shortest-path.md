---
layout: post
alias: "/blog/2017/12/31/hackerrank-world-codesprint-12-red-knights-shortest-path/"
title: "HackerRank World CodeSprint 12: Red Knight's Shortest Path"
date: "2017-12-31T16:26:26+09:00"
tags: [ "competitive", "writeup", "hackerrank", "codesprint", "bfs", "reconstruct" ]
"target_url": [ "https://www.hackerrank.com/contests/world-codesprint-12/challenges/red-knights-shortest-path" ]
---

## solution

縮退したDijkstra(つまり普通のBFS)をして経路復元。$O(N^2)$。

## implementation

``` c++
#include <climits>
#include <cstdio>
#include <queue>
#include <tuple>
#include <vector>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
using namespace std;

const int dy[] = { -2, -2, 0, 2, 2, 0 };
const int dx[] = { -1, 1, 2, 1, -1, -2 };
const char *name[] = { "UL", "UR", "R", "LR", "LL", "L" };
int main() {
    // input
    int n, y0, x0, y1, x1; scanf("%d%d%d%d%d", &n, &y0, &x0, &y1, &x1);
    // solve
    // // dp
    vector<vector<int> > dp(n, vector<int>(n, INT_MAX));
    queue<pair<int, int> > que;
    dp[y1][x1] = 0;
    que.emplace(y1, x1);
    while (not que.empty()) {
        int y, x; tie(y, x) = que.front(); que.pop();
        REP (i, 6) {
            int ny = y + dy[i];
            int nx = x + dx[i];
            if (0 <= ny and ny < n and 0 <= nx and nx < n) {
                if (dp[ny][nx] == INT_MAX) {
                    dp[ny][nx] = dp[y][x] + 1;
                    que.emplace(ny, nx);
                }
            }
        }
    }
    if (dp[y0][x0] == INT_MAX) {
        printf("Impossible\n");
        return 0;
    }
    // // construct
    vector<char const *> result;
    for (int y = y0, x = x0; dp[y][x]; ) {
        REP (i, 6) {
            int ny = y + dy[i];
            int nx = x + dx[i];
            if (0 <= ny and ny < n and 0 <= nx and nx < n) {
                if (dp[ny][nx] < dp[y][x]) {
                    y = ny;
                    x = nx;
                    result.push_back(name[i]);
                    break;
                }
            }
        }
    }
    // output
    int dist = result.size();
    printf("%d\n", dist);
    REP (i, dist) {
        printf("%s%c", result[i], i < dist - 1 ? ' ' : '\n');
    }
    return 0;
}
```
