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

from .events import EventManager, eventmgr_rfc1459

running_context = None

def get_context():
    global running_context
    return running_context

from .config import ConfigHandler
from .utility import CaseInsensitiveDict, ExpiringDict
from .channel import ChannelManager

import logging
import asyncio
import sys
import time
import os
import importlib

class ServerContext(object):
    options = []
    clients = CaseInsensitiveDict()
    channels = CaseInsensitiveDict()
    listeners = []
    config_name = 'mammond.yml'
    nofork = False

    def __init__(self):
        self.logger = logging.getLogger('')
        self.logger.setLevel(logging.DEBUG)

        self.chmgr = ChannelManager(self)
        self.client_history = ExpiringDict(max_len=1024, max_age_seconds=86400)

        self.handle_command_line()

        if not self.nofork:
            self.daemonize()

        self.logger.info('mammon - starting up, config: {0}'.format(self.config_name))
        self.eventloop = asyncio.get_event_loop()

        self.logger.debug('parsing configuration...')
        self.handle_config()

        self.logger.debug('init finished...')

        self.startstamp = time.strftime('%a %b %d %Y at %H:%M:%S %Z')

    def daemonize(self):
        self.pid = os.fork()
        if self.pid < 0:
            sys.exit(1)
        if self.pid != 0:
            sys.exit(0)
        self.pid = os.setsid()
        if self.pid == -1:
            sys.exit(1)
        devnull = "/dev/null"
        if hasattr(os, "devnull"):
            devnull = os.devnull
        devnull_fd = os.open(devnull, os.O_RDWR)
        os.dup2(devnull_fd, 0)
        os.dup2(devnull_fd, 1)
        os.dup2(devnull_fd, 2)

    def usage(self):
        cmd = sys.argv[0]
        print("""{0} [options]
A useless ircd.

Options:
   --help              - This screen.
   --debug             - Enable debug verbosity
   --nofork            - Do not fork into background
   --config config     - A JSON configuration file to parse""".format(cmd))
        exit(1)

    def handle_command_line(self):
        if '--help' in sys.argv:
            self.usage()
        if '--config' in sys.argv:
            try:
                self.config = sys.argv[sys.argv.index('--config') + 1]
            except IndexError:
                print('mammon: error: no parameter provided for --config')
                exit(1)
        if '--debug' in sys.argv:
            self.logger.basicConfig(format='%(asctime)s %(message)s', level=logging.DEBUG)
        if '--nofork' in sys.argv:
            self.nofork = True

    def handle_config(self):
        self.conf = ConfigHandler(self.config_name, self)
        self.conf.process()
        self.open_listeners()
        self.open_logs()
        self.load_modules()

    def open_listeners(self):
        [self.eventloop.create_task(lstn) for lstn in self.listeners]

    def load_module(self, mod):
        try:
            importlib.import_module(mod)
        except:
            self.logger.info('rejecting module ' + mod + ' because it failed to import')

    def load_modules(self):
        [self.load_module(m) for m in self.conf.extensions]

    def open_logs(self):
        if self.conf.logs:
            for log in self.conf.logs:
                fh = logging.FileHandler(log['path'])
                fh.setLevel(logging.DEBUG)
                self.logger.addHandler(fh)

    def run(self):
        global running_context
        running_context = self

        self.eventloop.run_forever()
        exit(0)
