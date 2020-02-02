---
category: blog
layout: post
title: "日本語ocrをinstallした"
date: 2013-12-06T14:57:47+09:00
tags: [ "install", "ocr" ]
---

[nhocr](http://code.google.com/p/nhocr/) and [tesseract](http://code.google.com/p/tesseract-ocr/)

日本語ではnhocrが、英数字ではtesseractが良いようだ


<!-- more -->

## tesseract
日本語専用ではない

### install
``` sh
sudo apt-get install tesseract-ocr tesseract-ocr-jpn
```
簡単

### test
``` sh
# tesseract 3.02.01
$ convert -font /usr/share/fonts/truetype/fonts-japanese-gothic.ttf -pointsize 32 label:'こんにちは 世界' a.pbm
$ tesseract a.pbm a -l jpn -psm 7 2>/dev/null ; cat a.txt
こん~二ち【ま 世界
```
倍角文字やギャル文字の自動生成に使えそうだと思ったが

``` sh
$ convert -font /usr/share/fonts/truetype/fonts-japanese-gothic.ttf -pointsize 32 label:'超絶核爆' -geometry 200%x100% a.pbm
$ tesseract a.pbm a -l jpn -psm 7 2>/dev/null ; cat a.txt
超絶核曝
```
と、漢字には強いようだ  
表音文字より表意文字の方が得意とは驚きである


## nhocr

### install
少し嵌まった  
prefixの指定が必須のようだ

``` sh
# cd O2-tools
./configure --prefix=/usr/local
make
sudo make install
# cd nhocr
./configure --prefix=/usr/local --with-O2tools=/usr/local
make
sudo make install
```

### test
``` sh
# NHocr - Japanese OCR  v0.21
$ convert -font /usr/share/fonts/truetype/fonts-japanese-gothic.ttf -pointsize 32 label:'こんにちは 世界' a.pbm
$ nhocr -o - -line a.pbm
こんにちは世界
```
問題ない  
しかし非常にきれいな画像での結果なので、実際に使うと違ってくるかもしれない


## 日本語以外の比較
``` sh
$ convert -pointsize 32 label:'Hello World' a.pbm
$ nhocr -o - -line a.pbm
H引foWohd
$ tesseract a.pbm a -l jpn -psm 7 2>/dev/null ; cat a.txt
Heーー。 W。「ーd
$ tesseract a.pbm a -psm 7 2>/dev/null ; cat a.txt
Hello World

$ convert -pointsize 32 label:'2.71828183' a.pbm
$ nhocr -o - -line a.pbm
2.7i828i88
$ tesseract a.pbm a -l jpn -psm 7 2>/dev/null ; cat a.txt
2'7ー 828ー 83
$ tesseract a.pbm a -psm 7 2>/dev/null ; cat a.txt
2.71828183
```
日本語以外ではtesseract(-l jpn 無し)が強い  
予想通りの結果


## 他のlibrary
[tomoe](http://tomoe.sourceforge.jp/cgi-bin/ja/blog/index.rb)
