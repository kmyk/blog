---
category: blog
layout: post
date: 2014-11-19T10:38:32+09:00
tags: [ "dbus", "python", "notify-send", "libnotify" ]
---

# Desktop通知サーバーについて調べた

ubuntuに標準で入ってる、「email届いたよ」「battery少なくなってるよ」などの通知を右上あたりに表示してくれるあの子

通知を送るには

``` sh
$ notify-send 'hello world'
```

で済むけど、受け取る側を作りたかった


<!-- more -->

## 構造

図で示す  
dbusでのprotocolはfreedesktop.orgが関与していて、特定の環境に依存していない

``` plain
                dbus-daemon
                 |       ^
            dbus |       | dbus
                 v       |
notification-server     user-applications
```

`libnotify`というライブラリはuser側のためのもの  
server側に関してはdbusを叩くしかないらしい


## dbus

`dbus-send`や`dbus-monitor`というコマンド、あるいは`d-feet`というGUIツールを使うとよい  
例えば以下のようにすれば、`notify-send`が送ったメッセージが読める

``` sh
$ dbus-monitor destination=org.freedesktop.Notifications &
$ notify-send foo bar
```

`dbus-send`で送る構文は

``` sh
$ dbus-send [--system] --dest=BUS_NAME [--type=method_call] [--print-reply] OBJECT_PATH INTERFACE [TYPE:VALUE ...]
```

例えば通知サーバの情報を得るには

``` sh
$ dbus-send --dest=org.freedesktop.Notifications --type=method_call --print-reply /org/freedesktop/Notifications org.freedesktop.Notifications.GetServerInformation
method return sender=:1.195 -> dest=:1.202 reply_serial=2
   string "notify-osd"
   string "Canonical Ltd"
   string "1.0"
   string "1.1"
```

ただし`dbus-send`は`dict`の要素としての`variant`が使えないので、通知を発生させることはできない[^1]ので注意


## api

仕様([Desktop Notifications Specification](https://developer.gnome.org/notification-spec/))の*D-BUS Protocol*の項  
直接に通知が来るのが`org.freedesktop.Notifications.Notify`

### variant
notify-osdの`org.freedesktop.Notifications.Notify`の型は`susssasa{sv}i`[^2]であるが、`variant`を`string`で置き換え`susssasa{ss}i`としたものも動く  
`libnotify`が上手く処理してくれているのだと思う


## code
以上を触りながら調べた際の副産物のコード  
既存の通知サーバを殺して[^3]から起動する

[statnot](https://github.com/halhen/statnot)から切り出したものなので`GPLv2`

``` python
#!/usr/bin/python3

import gi.repository.GLib
import dbus
import dbus.service
import dbus.mainloop.glib

NOTIF_BUS_NAME    =  'org.freedesktop.Notifications'
NOTIF_OBJECT_PATH = '/org/freedesktop/Notifications'
NOTIF_INTERFACE   =  'org.freedesktop.Notifications'

class NotificationServer(dbus.service.Object):
    _id = 0

    @dbus.service.method(NOTIF_INTERFACE,
                         in_signature='susssasa{sv}i',
                         out_signature='u')
    def Notify(self, app_name, replace_id, app_icon,
               summary, body, actions, hints, expire_timeout):
        if not replace_id:
            self._id += 1
            notification_id = self._id
        print( { 'app_name' : app_name
               , 'notification_id' : notification_id
               , 'app_icon' : app_icon
               , 'summary' : summary
               , 'body' : body
               , 'actions' : actions
               , 'hints' : hints
               , 'expire_timeout' : expire_timeout
               } )
        return notification_id

    @dbus.service.method(NOTIF_INTERFACE, in_signature='', out_signature='as')
    def GetCapabilities(self):
        return ('body', )

    @dbus.service.signal(NOTIF_INTERFACE, signature='uu')
    def NotificationClosed(self, id_in, reason_in):
        pass

    @dbus.service.method(NOTIF_INTERFACE, in_signature='u', out_signature='')
    def CloseNotification(self, id):
        pass

    @dbus.service.method(NOTIF_INTERFACE, in_signature='', out_signature='ssss')
    def GetServerInformation(self):
        return ('developping', 'http://localhost', '0.0.1', '1.2') # name vendor version spec_version

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    args = parser.parse_args()

    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SessionBus()
    name = dbus.service.BusName(NOTIF_BUS_NAME, bus, do_not_queue=True) # don't remove the binding: to avoid to call dtor
    NotificationServer(bus, NOTIF_OBJECT_PATH)
    mainloop = gi.repository.GLib.MainLoop()
    mainloop.run() # don't quit
```

## 参考
-   [Desktop notifications \(日本語\) - ArchWiki](https://wiki.archlinux.org/index.php/Desktop_notifications_(%E6%97%A5%E6%9C%AC%E8%AA%9E))
-   [Desktop Notifications Specification](https://developer.gnome.org/notification-spec/) (Version 1.2)
-   [D-Bus の存在を感じてみる](http://www.usupi.org/sysad/175.html)
-   [Libnotify Reference Manual](https://developer.gnome.org/libnotify/0.7/)

---

# Desktop通知サーバーについて調べた

[^1]: `variant`を使わないサーバーに対しては送れる
[^2]: `string * uint32 * string * string * string * array{string} * dict{string,variant} * int32`の意
[^3]: ubuntu 14.10だと`$ killall notify-osd`
