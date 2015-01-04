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

from ircreactor.events import EventManager

eventmgr = EventManager()
running_context = None

def get_context():
    global running_context
    return running_context

from .config import ConfigHandler
#from .client import ClientProtocol

import logging
import asyncio
import sys

class ServerContext(object):
    options = []
    clients = []
    listeners = []
    config_name = 'mammond.conf'

    def __init__(self):
        self.handle_command_line()

        logging.info('mammon - starting up, config: {0}'.format(self.config_name))
        self.eventloop = asyncio.get_event_loop()

        logging.debug('parsing configuration...')
        self.handle_config()

        logging.debug('init finished...')

    def usage(self):
        cmd = sys.argv[0]
        print("""{0} [options]
A useless ircd.

Options:
   --help              - This screen.
   --debug             - Enable debug verbosity
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
            logging.basicConfig(format='%(asctime)s %(message)s', level=logging.DEBUG)

    def handle_config(self):
        self.conf = ConfigHandler(self.config_name, self)
        self.conf.process()
        self.open_listeners()

    def open_listeners(self):
        [self.eventloop.create_task(lstn) for lstn in self.listeners]

    def run(self):
        global running_context
        running_context = self

        logging.debug('running_context: {0}'.format(id(running_context)))
        self.eventloop.run_forever()
        exit(0)
