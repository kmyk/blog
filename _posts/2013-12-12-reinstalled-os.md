---
category: blog
layout: post
title: "os入れ直した"
date: 2013-12-12T02:18:26+09:00
tags: [ "install", "arch", "xfce", "fcitx", "memo" ]
---

XUbuntu, xmonad, fcitx + mozc  
導入のメモ

<!-- more -->

1. ubuntuでGDMからloginできなくなった
    - おそらくupdateが原因、ちゃんと調べてないのでよく分からない
2. 良い機会だということでarchを入れた
3. 音が出ないなどしたのでxubuntuに逃げた

## Arch Linux
次に挑戦する時のために

### install
[install.txt](https://wiki.archlinux.org/index.php/Installation_Guide)をよく読んでinstall  
locale-genを忘れてcan't set the localeとか言われまくって悩んだ

### sudo
よく分からなかったので/etc/sudoersに無理やり追記した  
`echo $USER ALL=\(ALL\) ALL >> /etc/sudoers` 的な

### GUI環境
`pacman -S xfce4`  
gnomeは入れたが起動失敗するのでやめた

`pacman -S xmonad` し  
Session and Startup (xfce4-session-settings) -> Application Autostart に `xmonad --replace` を追加

### 日本語入力
fcitxを導入することに  
`pacman -S fcitx fcitx-mozc fcitx-configtool`  
変換/無変換をon/offに割り当て

fcitxは~/.Xmodmapがあれば読み込むらしく、xmodmap使ってる人には嬉しい

### mount権限の追加
polkitなるものを導入  
適当なgroup作って権限付与

```
# /etc/polkit-1/rules.d/10-enable-mount.rules
polkit.addRule(function(action, subject) {
if (action.id == "org.freedesktop.udisks2.filesystem-mount-system" && subject.isInGroup("adm")) {
    return polkit.Result.YES;
}
});
```

### 無線
調子悪い

頻繁に切れ

``` sh
$ ping 192.168.2.1
connect: Network is unreachable
```
となるなど

### 音声
出ない  
出ない


## XUbuntu

### 無線
何故か調子が良い

### 音声
理由はわからないが出る  
xfceのpanel上のiconからは一切操作できないが、thinkpadのkeyboardの音量関連のkeyを通して操作可

### xfce, sudo, polkit
導入済み

### 日本語入力
同じくfcitxをinstall -> 問題発生 -> 解決

[Ubuntu 13.10 で fcitx-mozc を使う - 部屋の中にも一年](http://itiut.hatenablog.com/entry/2013/10/25/145408)

>   japanese-testersのリポジトリを追加。
>   デフォルトのリポジトリのFicitxだと、IMオンのホットキーがIMのトグルとして動き、IMオフのホットキーが何も動作しないバグ？が起こりました。
>   ```
>       $ sudo add-apt-repository ppa:japanese-testers/ppa
>       $ sudo apt-get update
>   ```

### xmonad
自動起動してくれない問題が発生した  
環境変数の不足(PATH)により~/.xmonad/xmonad.hs内でこけていた  
application autostartのxmonadのcommandを`zsh -c 'xmonad --replace'`として、無理やり~/.zshenvを読ませることにより解決

試行錯誤中にSettings Editor (xfce4-settings-editor) -> xfce4-session -> session/Failsafe/Client0_commandなる項目を見つけた  
初期値が["xfwm4", "--replace"]とものすごくwindow manager関連ぽい  
しかし`xfconf-query -c xfce4-session -p /sessions/Failsafe/Client0_Command -t string -s xmonad -t string -s --replace -a`などとして設定しても、起動している様子が見られなかった  
他の方法で解決したので放置

- [Xmonad/Using xmonad in XFCE - HaskellWiki](http://www.haskell.org/haskellwiki/Xmonad/Using_xmonad_in_XFCE)
- [Xfce - ArchWiki # Window Manager](https://wiki.archlinux.org/index.php/xfce#Window_Manager)
- [An Introduction to the Z Shell - Startup Files](http://zsh.sourceforge.net/Intro/intro_3.html)

### トラボ
thinkpadとの相性でhotplugできない問題継続中  
抱き合わせのwindows上ですらできないのだから諦めている

### 画面
thinkpadの問題その２  
以前からsuspend後に画面の電源がつかなかった  
さらに蓋を閉じてもアウトに  
これは治せるだろうが面倒なので放置
