---
layout: post
redirect_from:
  - /writeup/golf/atcoder/abc_039_c/
  - /writeup/golf/atcoder/abc-039-c/
  - /blog/2016/06/11/abc-039-c/
date: 2016-06-11T23:00:03+09:00
tags: [ "competitive", "writeup", "atcoder", "abc", "sed", "golf" ]
"target_url": [ "https://beta.atcoder.jp/contests/abc039/tasks/abc039_c" ]
---

# AtCoder Beginner Contest 039 C - ピアニスト高橋君

けっこう手間取った

## implementation

### sed 108byte

``` sed
s/^/WBWBWWBWBWBW DoReMFaSoLaSi/
:
/^\(\w*\) .*i\1/!s/^\(.\)\(\w*\) ./\2\1 /
t
s/.* \(..\).*/\1/
s/F$/i/
```

atcoderは改行が`\r\n`なので、`;`にすれば5byte減る。(忘れていた)

<hr>

また、%20さんが以下を提出しているので見るとよい

-   54byteのsed: <https://beta.atcoder.jp/contests/abc039/submissions/764960>
-   52byteのperl (全言語最短): <https://beta.atcoder.jp/contests/abc039/submissions/764805>
