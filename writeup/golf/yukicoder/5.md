---
layout: post
redirect_from:
  - /writeup/golf/yukicoder/5/
  - /blog/2016/09/24/yuki-5/
date: "2016-09-24T11:41:10+09:00"
tags: [ "competitive", "writeup", "yukicoder", "golf", "perl" ]
"target_url": [ "http://yukicoder.me/problems/no/5" ]
---

# Yukicoder No.5 数字のブロック

私の提出 ($59$byte):

``` perl
$l=<>;<>;$a+=0<=($l-=$_)for sort{$a<=>$b}split$",<>;print$a
```

tailsさんの提出 ($46$byte) <http://yukicoder.me/submissions/71789>:

``` perl
$-=<>+1;<>;print~~grep$--=$_,sort{$a-$b}glob<>
```

-   `split$",` $\to$ `glob`
-   `$a<=>$b` $\to$ `$a-$b`
-   `for` $\to$ `grep`
-   `grep`にblock `{$--=$_}`でなくexpr `$--=$_`を渡す
-   `~~`はlistからその長さを得る
