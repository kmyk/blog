---
category: blog
layout: post
title: "~/.ssh/configにHost githubと書くのは間違い"
date: "2018-06-09T00:04:05+09:00"
tags: [ "github", "ssh" ]
---

正解は `Host github.com` です。

## 詳細

秘密鍵を `~/.ssh/id_rsa.github.com` に置くとすると、完全な形としては次が正しい:

```
Host github.com
    User git
    IdentityFile ~/.ssh/id_rsa.github.com
```

`Host github` や `Host GitHub` などとすると(`git` コマンド経由では)設定が読み込まれない。
ただし秘密鍵が `~/.ssh/id_rsa` にあれば `~/.ssh/config` での設定とは独立にそれが読み込まれることに注意。

`Host github` と記述した場合、 `ssh` コマンド経由で `$ ssh github` などとしたときのみ設定が読み込まれる (`$ ssh github.com` では読み込まれない)。
しかしそのままでは `github` (`github.com` ではない) というhostに接続しようとしてしまうので `HostName github.com` を加える必要がある。
なおこのようにして `$ ssh github` を実行しても接続テストができるだけである。

設定に失敗していると次のような `Permission denied (publickey).` のエラーがでる:

``` sh
ubuntu@ik0-000-00000:~$ git clone git@github.com:kmyk/dotfiles.git
Cloning into 'dotfiles'...
git@github.com: Permission denied (publickey).
fatal: Could not read from remote repository.

Please make sure you have the correct access rights
and the repository exists.
```

記述時現在で手元から [`github ssh`](https://www.google.co.jp/search?q=github+ssh) とGoogle検索すると上位4ページ中3ページがこの問題を抱えていた。
公式のtutorial <https://help.github.com/articles/connecting-to-github-with-ssh/> にすべてきちんと従えばこの問題を踏むことはない。
