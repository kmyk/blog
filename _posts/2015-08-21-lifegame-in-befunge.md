---
category: blog
layout: post
date: 2015-08-21T02:25:02+09:00
tags: [ "befunge", "esolang", "lifegame" ]
---

# befungeでライフゲーム書いた

思っていたより人にやさしい言語だったので勢いで作った。
命令そのものは`Befunge-93`の範囲で書いたが、`Befunge-93`にはソースコードのサイズの制限があるらしいので、正確には`Funge-98`だと思われる。

ところで、コンパイラのオプションを眺めていると`FILE`や`SOCK`などとあって驚く。実用言語でも目指しているのだろうか。

<!-- more -->

``` plain
##  v YX    00g:Y 10g:X
##  v PQ    01g:P 11g:Q
  # v  T          22g:T
    v
    v
    v
    v
    v
    v   #         99g:100

  #   SET CONSTANTS
  # > 455**99p v
  # v          <

  #   INITIALIZE CELLS
  # >   055*-00p > 0445**-10p v        v#                   <
  #                                 > >?0> 10g00gp 10g1+10p ^
  #                           > 10g |  >1^
  #              | g00 p00+1g00     <
  # v            <

  #   INITIALIZE CORNER OF TEMPORARY CELLS
  # >   039*-00p > 0199*+-10p v     > 0 10g99g-1+ 00g99g-1+ p 10g1+10p v
  #   >          ^            > 10g |
  #   | g00 p00+1g00                <
  # v <                       ^                                        <

  #   DISPLAY CELLS
> # >   055*-00p > 0445**-10p v                      >"7",v
  #                                 > 39*,10g00gg"[",|    >" m",, 10g1+10p v
  #   >          ^            > 10g |                >"0",^
  #   | g00 p00+1g00 ,*25           <
  # v <                       ^                                            <

  #   COPY CELLS TO TEMPORARY CELLS
  # >   055*-00p > 0445**-10p v     > 10g00gg 10g99g- 00g99g- p 10g1+10p v
  #   >          ^            > 10g |
  #   | g00 p00+1g00                <
  # v <                       ^                                          <

  #   UPDATE CELLS
  # >    055*-00p > 0445**-10p v                                                          <
  #                                                    >22g3-!22g4-!+!!v LIVE: 2, 3
  #                                  >  022p v> 10g00gg|      >        > 10g00gp 10g1+10p ^
  #   >           ^            > 10g |                 >22g3-!^ BIRTH: 3
  #   |  g00 p00+1g00                <>       ^
  # v <                                v     <       v                                                      <
  #                                    > 301p > 311p v     > 10g99g-11g+2- 00g99g-01g+2- g 22g+22p 11g1-11p ^
  #                                    >      ^      > 11g |
  #                                    | g10 p10-1g10      <  COUNT NEIGHBORS
  #                                   ^<

  #   BUSY WAITING        v     <
  # > 99*9*9*9*           > 1-: |
  # v                         $ <

  #   MOVE CURSOR
  # > 39*, "A52[",,,, v
  # v                 <

^   <
```
