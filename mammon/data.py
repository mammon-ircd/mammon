#!/usr/bin/env python
# mammon - a useless ircd
#
# Copyright (c) 2015, William Pitcock <nenolod@dereferenced.org>
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

import json
import os
import threading

from .server import get_context

class DataStore:
    def __init__(self):
        ...

    def create_or_load(self):
        ctx = get_context()
        self.format = ctx.conf.data['format']

        if self.format == 'json':
            self._store = {}
            self._store_lock = threading.Lock()

            self._filename = os.path.abspath(os.path.expanduser(ctx.conf.data['filename']))

            ctx.logger.debug('loading json data store from {}'.format(self._filename))

            if os.path.exists(self._filename):
                self._store = json.loads(open(self._filename, 'r').read())
        else:
            raise Exception('Data store format [{}] not recognised'.format(self.format))

    def save(self):
        if self.format == 'json':
            with open(self._filename, 'w') as store_file:
                store_file.write(json.dumps(self._store))
        else:
            raise Exception('Data store format [{}] not recognised'.format(self.format))

    # single keys
    def __contains__(self, key):
        if self.format == 'json':
            return key in self._store
        else:
            raise Exception('Data store format [{}] not recognised'.format(self.format))

    def get(self, key, default=None):
        if self.format == 'json':
            return self._store.get(key, default)
        else:
            raise Exception('Data store format [{}] not recognised'.format(self.format))

    def put(self, key, value):
        if self.format == 'json':
            # make sure we can serialize the given data
            # so we don't choke later on saving the db out
            json.dumps(value)

            self._store[key] = value

            return True
        else:
            raise Exception('Data store format [{}] not recognised'.format(self.format))

    def delete(self, key):
        if self.format == 'json':
            try:
                with self._store_lock:
                    del self._store[key]
            except KeyError:
                # key is already gone, nothing to do
                ...

            return True
        else:
            raise Exception('Data store format [{}] not recognised'.format(self.format))

    # multiple keys
    def list_keys(self, prefix=None):
        """Return all key names. If prefix given, return only keys that start with it."""
        if self.format == 'json':
            keys = []

            with self._store_lock:
                for key in self._store:
                    if prefix is None or key.startswith(prefix):
                        keys.append(key)

            return keys
        else:
            raise Exception('Data store format [{}] not recognised'.format(self.format))

    def delete_keys(self, prefix):
        """Delete all keys with the given prefix."""
        if self.format == 'json':
            with self._store_lock:
                for key in tuple(self._store):
                    if key.startswith(prefix):
                        del self._store[key]
        else:
            raise Exception('Data store format [{}] not recognised'.format(self.format))
