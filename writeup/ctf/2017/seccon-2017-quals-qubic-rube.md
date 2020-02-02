---
layout: post
alias: "/blog/2017/12/10/seccon-2017-quals-qubic-rube/"
title: "SECCON 2017 Online CTF: Qubic Rube"
date: "2017-12-10T15:18:17+09:00"
tags: [ "ctf", "writeup", "seccon", "seccon-quals", "ppc", "pillow", "qr-code", "implementation" ]
"target_url": [ "https://ctftime.org/event/512/" ]
---

## problem

There are rubic cubes which sides are drawn QR-codes. Solve and decode them.

## solution

just implement it. not so difficult

## implementation

``` python
#!/usr/bin/env python3
import io
import itertools
import PIL.Image
import pyzbar.pyzbar as pyzbar
import requests

def download_images(stage):
    for c in 'RLUDFB':
        url = 'http://qubicrube.pwn.seccon.jp:33654/images/{}_{}.png'.format(stage, c)
        print('[*] GET', url)
        yield requests.get(url).content

WIDTH, HEIGHT = 246, 246
SIZE = 246 // 3

def split_image(image):
    width, height = image.size
    assert width == height == WIDTH == HEIGHT
    for y in range(0, height, SIZE):
        for x in range(0, width, SIZE):
            yield image.copy().crop(( x, y, x + SIZE, y + SIZE ))

color_dict = {
    (196, 30, 58): 'R',
    (255, 88, 0): 'O', # range
    (255, 255, 255): 'W',
    (0, 81, 186): 'B',
    (0, 158, 96): 'G',
    (255, 213, 0): 'Y',
}

def detect_color(image):
    width, height = image.size
    for y in range(0, height, 10):
        for x in range(0, width, 10):
            color = image.getpixel(( x, y ))
            r, g, b = color
            if r or g or b:
                assert color in color_dict
                return color_dict[color]

def solve(stage):
    parts = {}
    for color in 'ROWBGY':
        parts[color] = {}
        for position in 'ABC':
            parts[color][position] = []
    for data in download_images(stage):
        image = PIL.Image.open(io.BytesIO(data))
        splitted = split_image(image)
        a = []
        a += [ [ next(splitted), next(splitted), next(splitted) ] ]
        a += [ [ next(splitted), next(splitted), next(splitted) ] ]
        a += [ [ next(splitted), next(splitted), next(splitted) ] ]
        parts[detect_color(a[0][0])]['C'] += [ a[0][0] ]
        parts[detect_color(a[0][1])]['B'] += [ a[0][1] ]
        parts[detect_color(a[0][2])]['C'] += [ a[0][2].copy().transpose(PIL.Image.ROTATE_90) ]
        parts[detect_color(a[1][0])]['B'] += [ a[1][0].copy().transpose(PIL.Image.ROTATE_270) ]
        parts[detect_color(a[1][1])]['A'] += [ a[1][1] ]
        parts[detect_color(a[1][2])]['B'] += [ a[1][2].copy().transpose(PIL.Image.ROTATE_90) ]
        parts[detect_color(a[2][0])]['C'] += [ a[2][0].copy().transpose(PIL.Image.ROTATE_270) ]
        parts[detect_color(a[2][1])]['B'] += [ a[2][1].copy().transpose(PIL.Image.ROTATE_180) ]
        parts[detect_color(a[2][2])]['C'] += [ a[2][2].copy().transpose(PIL.Image.ROTATE_180) ]
    result = []
    for color in 'ROWBGY':
        found = False
        for c in itertools.permutations(parts[color]['C']):
            for b in itertools.permutations(parts[color]['B']):
                a, = parts[color]['A']
                for _ in range(4):
                    a = a.copy().transpose(PIL.Image.ROTATE_90)
                    image = PIL.Image.new('RGB', (WIDTH, HEIGHT))
                    image.paste(c[0], (0, 0))
                    image.paste(b[0], (SIZE, 0))
                    image.paste(c[1].copy().transpose(PIL.Image.ROTATE_270), (2 * SIZE, 0))
                    image.paste(b[1].copy().transpose(PIL.Image.ROTATE_90), (0, SIZE))
                    image.paste(a, (SIZE, SIZE))
                    image.paste(b[2].copy().transpose(PIL.Image.ROTATE_270), (2 * SIZE, SIZE))
                    image.paste(c[2].copy().transpose(PIL.Image.ROTATE_90), (0, 2 * SIZE))
                    image.paste(b[3].copy().transpose(PIL.Image.ROTATE_180), (SIZE, 2 * SIZE))
                    image.paste(c[3].copy().transpose(PIL.Image.ROTATE_180), (2 * SIZE, 2 * SIZE))
                    image = image.convert('L').point(lambda x: 255 if x else 0)  # binary
                    for decoded in pyzbar.decode(image):
                        decoded = decoded.data.decode()
                        result += [ decoded ]
                        print('[+] {}: {}'.format(color, decoded))
                        if decoded.strip() in [ 'Next URL is:', 'Qubic Rube', 'SECCON 2017 Online CTF', 'Have fun!', 'Go! Go!', 'The flag is:' ] or decoded.startswith('No. ') or decoded.startswith('http://'):
                            found = True
                    if found:
                        break
                if found:
                    break
            if found:
                break
    return result


stage = '01000000000000000000'
while stage:
    print('[!] stage:', stage)
    result = solve(stage)
    stage = None
    for s in result:
        if s.startswith('http://'):
            stage = s.split('/')[-1]
```
