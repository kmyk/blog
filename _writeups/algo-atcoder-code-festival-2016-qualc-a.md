---
layout: post
redirect_from:
  - /writeup/algo/atcoder/code-festival-2016-qualc-a/
  - /blog/2016/10/23/code-festival-2016-qualc-a/
date: "2016-10-23T23:00:10+09:00"
tags: [ "competitive", "writeup", "atcoder", "codefestival", "golf", "sed", "brainfuck" ]
"target_url": [ "https://beta.atcoder.jp/contests/code-festival-2016-qualc/tasks/codefestival_2016_qualC_a" ]
---

# CODE FESTIVAL 2016 qual C: A - CF

## implementation

### sed 14byte

`\r`の1byteを削る魔法により$1$位を得た。

``` sed
/C.*F/cYes
cNo
```

### brainfuck

E問題が解けなかったので代わりに書いた。$1$行目だけgolfしたけど`Yes`/`No`は楽しくないので放棄。cheatしたい。

``` brainfuck
#!/usr/bin/env bf
++>>,+[--<++++++++[>---------<-]<[>+>+++<<-]>[->[[-]<+>]]>,+]<+<
Yes [>>++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++.+++++++++++++++++++++++++++++++++.>]
No >[>+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++.++++++++++++.++++++++++++++.>]
```
