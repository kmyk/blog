---
layout: post
alias: "/blog/2016/11/19/qiwi-infosec-ctf-2016-ppc-400/"
date: "2016-11-19T01:30:54+09:00"
tags: [ "ctf", "writeup", "qiwi-ctf", "ppc", "sqlite", "dijkstra" ]
---

# Qiwi Infosec CTF 2016: PPC 400

sqliteの`maze.db`から迷路を読み込んで解く。$50 \times 50$なので余裕だが、flagは$695$文字と大きくて驚く。

``` python
#!/usr/bin/env python3

# read maze.db
import sqlite3
## sqlite> .schema
## CREATE TABLE start (id integer);
## CREATE TABLE finish (id integer);
## CREATE TABLE points
##                      (id integer primary key,
##                       x integer, y integer, status varchar(10), value varchar(1));
with sqlite3.connect('maze.db') as conn:
    row, = conn.execute('select id from start')
    start, = row
    row, = conn.execute('select id from finish')
    finish, = row
    points = [ [ None for _ in range(50) ] for _ in range(50) ]
    for id_, x, y, status, value in conn.execute('select id, x, y, status, value from points'):
        assert status in [ 'wall', 'gate' ]
        points[y][x] = { 'status': status, 'value': value }
        if id_ == start:
            start = (y, x)
        elif id_ == finish:
            finish = (y, x)

# debug draw
for y in range(50):
    for x in range(50):
        c = points[y][x]['value']
        if points[y][x]['status'] == 'wall':
            c = '\033[47m' + c + '\033[0m'
        print(c, end='')
    print()

# dijkstra
from heapq import heappush, heappop
heap = []
dist = [ [ None for _ in range(50) ] for _ in range(50) ]
y, x = start
value = points[y][x]['value']
heappush(heap, (len(value), y, x, value))
dist[y][x] = points[y][x]['value']
while heap:
    _, y, x, value = heappop(heap)
    for dy, dx in [ (-1, 0), (1, 0), (0, 1), (0, -1) ]:
        ny = y + dy
        nx = x + dx
        if 0 <= ny < 50 and 0 <= nx < 50:
            if points[ny][nx]['status'] == 'gate' and dist[ny][nx] is None:
                nvalue = value + points[ny][nx]['value']
                dist[ny][nx] = nvalue
                heappush(heap, (len(nvalue), ny, nx, nvalue))
y, x = finish
print(dist[y][x])
```

flag:

```
154C82F36487A9157315AADFDDED1BB83ECD98E49EADAFEB03DB563A94E0851478C408CFD6B0BB42B030F61A82E655B7FCA0E1FA68DF676758DC60FBFD1016F0EB8E7A2B5170A157497EF711E4009653BC9B20726C98B6561EFBE316AC2AB2DCBE56494F05B44ED3EB62DA4109BEEC2537266FEDE44ACB12A17CA8C8A5BA9E1A4D24ACAD900FFBD228AC187B9024BEDC941D137EA3A92F9F8506740CD8C62DBEDB9990F3E0259434D9FCF070FEC9E60C5697BABA83A4E59EB4C3F0E7AFD44B1B8D9D93933962B27237560B5F8F7D19904D790842FA596FBB52B2A3F7EE15B7F589D28A6F20F747615E7ED135E17AFE8FE073B6606F5C893D40CB78B635AA5FE4E0EE10C572D5E7AECEAF743953D05F78BBC10A9BB3D53B0011AE5F269C806E5F9E6026C954A0CDF9C797953360602B96FC06324C3160701505C24597F6F7C77D5B76CBE25CD2B706A41DA324A1B79CFC4BA8B11F800593514D27754
```
