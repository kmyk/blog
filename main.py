#!/usr/bin/env python3
import argparse
import io
import json
import pathlib
import re
import urllib.parse
from typing import *

import requests


class GROWI(object):
    def __init__(self, *, host: str):
        self.host = host

    def pages_list(self) -> Iterator[str]:
        resp = requests.get(f'https://{self.host}/_api/pages.list?path=/&limit=10000')
        data = json.loads(resp.content)
        if not data['ok']:
            raise RuntimeError(data['error'])
        for page in data['pages']:
            yield urllib.parse.unquote(page['path'])

    def pages_get_from_path(self, path: str) -> Dict[str, Any]:
        resp = requests.get(f'https://{self.host}/_api/pages.get?path={path}')
        resp.raise_for_status()
        data = json.loads(resp.content)
        if not data['ok']:
            raise RuntimeError(data['error'])
        return data['page']

    def pages_rename(self, page_id: str, *, revision_id: str, new_path: str, token: str) -> None:
        payload = {
            'page_id': page_id,
            'revision_id': revision_id,
            'new_path': new_path,
            'create_redirect': True,
        }
        resp = requests.post(f'https://{self.host}/_api/pages.rename?access_token={token}', data=payload)
        resp.raise_for_status()
        data = json.loads(resp.content)
        if not data['ok']:
            raise RuntimeError(data['error'])


def iterate_sync_items(*, api: GROWI) -> Iterator[Tuple[str, pathlib.Path, str]]:
    for src in api.pages_list():
        # print('[*] path:', src)
        m = re.fullmatch(r'/user/\w+/メモ/(\d\d\d\d)/(\d\d)/(\d\d)/(AtCoder|Codeforces|SRM|yukicoder|HackerRank)/(.+)', src)
        if m:
            year = m.group(1)
            month = m.group(2)
            day = m.group(3)
            a = m.group(4)
            b = m.group(5)
            print('[*] found:', (year, month, day, a, b))

            revision = api.pages_get_from_path(src)['revision']['body']
            if '[/' in revision or '](/' in revision:
                print('[!] failure')
                continue
            revision, _ = re.subn(r'(\s)(https?://\S+)', r'\1<\2>', revision)

            a = a.lower()
            if a == 'srm':
                a = 'topcoder'
            b = b.replace(' ', '-').replace('/', '-').lower()
            dst = pathlib.Path(f'writeup/algo/{a}/{b}.md')

            fh = io.StringIO()
            print('---', file=fh)
            print('layout: post', file=fh)
            print(f'date: {year}-{month}-{day}T23:59:59+09:00', file=fh)
            print(f'tags: ["competitive", "writeup"]', file=fh)
            print('---', file=fh)
            print(file=fh)
            print(revision.strip(), file=fh)
            yield (src, dst, fh.getvalue())


def sync(*, api: GROWI) -> None:
    for src, dst, content in list(iterate_sync_items(api=api)):
        with open(dst, 'w') as fh:
            fh.write(content)
        print('[*] written:', src, '->', dst)


def delete(*, api: GROWI, token: str) -> None:
    for path, _, _ in list(iterate_sync_items(api=api)):
        new_path = path.replace('/メモ', '/trash', 1)
        page = api.pages_get_from_path(path)
        api.pages_rename(page['_id'], revision_id=page['revision']['_id'], new_path=new_path, token=token)
        print('[*] moved:', path, '->', new_path)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=('sync', 'delete'))
    parser.add_argument('--host', default='wiki.kimiyuki.net')
    parser.add_argument('--token')
    args = parser.parse_args()

    api = GROWI(host=args.host)

    if args.command == 'sync':
        sync(api=api)

    elif args.command == 'delete':
        assert args.token
        delete(api=api, token=args.token)


if __name__ == "__main__":
    main()
