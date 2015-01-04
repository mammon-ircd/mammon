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

import asyncio
import logging
import time

from ircreactor.events import EventManager
from ircreactor.envelope import RFC1459Message
from .server import eventmgr, get_context

# XXX - handle ping timeout
# XXX - exit_client() could eventually be handled using eventmgr.dispatch()
class ClientProtocol(asyncio.Protocol):
    def connection_made(self, transport):
        self.ctx = get_context()
        self.ctx.clients.append(self)

        self.peername = transport.get_extra_info('peername')
        self.transport = transport
        self.recvq = list()
        self.channels = list()
        self.nickname = '*'
        self.username = str()
        self.hostname = self.peername  # XXX - handle rdns...
        self.registered = False
        self.registration_lock = 2     # NICK/USER steps

        logging.debug('new inbound connection from {}'.format(self.peername))

    def data_received(self, data):
        m = RFC1459Message.from_message(data.decode('UTF-8', 'replace').strip('\r\n'))
        m.client = self

        logging.debug('client {0} --> {1}'.format(repr(self.__dict__), repr(m.serialize())))
        if len(self.recvq) > self.ctx.conf.recvq_len:
            self.exit_client('Excess flood')
            return

        self.recvq.append(m)

        # XXX - drain_queue should be called on all objects at once to enforce recvq limits
        self.drain_queue()

    def drain_queue(self):
        while self.recvq:
            m = self.recvq.pop(0)
            eventmgr.dispatch(*m.to_event())

    def dump_message(self, m):
        self.transport.write(bytes(m.to_message() + '\r\n', 'UTF-8'))

    def dump_numeric(self, numeric, params):
        msg = RFC1459Message.from_data(numeric, source=self.ctx.conf.name, params=params)
        self.dump_message(msg)

    def dump_notice(self, message):
        msg = RFC1459Message.from_data('NOTICE', source=self.ctx.conf.name, params=['*** ' + message])
        self.dump_message(msg)

    @property
    def hostmask(self):
        if not self.registered:
            return None
        hm = self.nickname
        if self.username:
            hm += '!' + self.username
            if self.hostname:
                hm += '@' + self.hostname
        return hm

    def exit_client(self, message):
        m = RFC1459Message.from_data('QUIT', source=self.hostmask, params=[message])
        self.dump_message(m)
        while self.channels:
            i = self.channels.pop(0)
            i.clients.pop(self)
            i.dump_message(m)
        self.transport.close()
        if self.registered:
            self.ctx.clients.pop(self.nickname)

    def release_registration_lock(self):
        if self.registered:
            return
        self.registration_lock--
        if not self.registration_lock:
            self.register()

    def sendto_common_peers(self, message):
        [i.dump_message(message) for i in self.channels]
