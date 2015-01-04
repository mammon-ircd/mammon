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

try:
    import simplejson as json
except:
    import json

import asyncio
import logging
from .client import ClientProtocol

class ConfigHandler(object):
    config_st = {}
    ctx = None
    listener_protos = {
        'client': ClientProtocol,
    }

    def __init__(self, config_name, ctx):
        self.config_name = config_name
        self.ctx = ctx

        self.config_st = json.loads(open(config_name, 'r').read())

    def process(self):
        for k, v in self.config_st.items():
            setattr(self, k, v)

        for l in self.listeners:
            proto = l.get('proto', 'client')

            logging.info('opening listener at {0}:{1} [{2}]'.format(l['host'], l['port'], proto))
            lstn = self.ctx.eventloop.create_server(self.listener_protos[proto], l['host'], l['port'])
            self.ctx.listeners.append(lstn)
