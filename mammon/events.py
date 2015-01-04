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

# XXX
REGISTRATION_LOCK_NICK = 0x1
REGISTRATION_LOCK_USER = 0x2

import logging
from functools import wraps

from ircreactor.events import EventManager as EventManagerBase
from ircreactor.envelope import RFC1459Message

class EventManager(EventManagerBase):
    def __init__(self):
        super(EventManager, self).__init__()

    def dispatch(self, event, ev_msg):
        """Dispatch an event.
               event: name of the event (str)
               ev_msg: non-optional arguments dictionary.
           Side effects: None"""
        logging.debug('dispatching: ' + event + ': ' + repr(ev_msg))
        eo = self.events.get(event, None)
        if not eo:
            return self.handle_unknown(ev_msg)
        eo.dispatch(ev_msg)

    def handle_unknown(self, ev_msg):
        """Handle an unknown event.
              ev_msg: non-optional arguments dictionary.
           Side effects: None"""
        cli = ev_msg['client']
        msg = RFC1459Message.from_data('421', source=cli.ctx.conf.name, params=[cli.nickname, ev_msg['verb'], 'Unknown command'])
        cli.dump_message(msg)

    def connect(self, event):
        def wrapped_fn(func):
            self.register(event, func)
            return func
        return wrapped_fn

    def message(self, verb, min_params=0):
        def parent_fn(func):
            @wraps(func)
            def child_fn(ev_msg):
                cli = ev_msg['client']
                if len(ev_msg['params']) < min_params:
                    msg = RFC1459Message.from_data('461', source=cli.ctx.conf.name, params=[cli.nickname, ev_msg['verb'], 'Not enough parameters'])
                    cli.dump_message(msg)
                    return
                return func(cli, ev_msg)
            self.register('rfc1459 message ' + verb, child_fn)
            return child_fn
        return parent_fn

eventmgr = EventManager()

# - - - BUILTIN EVENTS - - -

@eventmgr.message('QUIT')
def m_QUIT(cli, ev_msg):
    reason = ev_msg['params'][0] if ev_msg['params'] else str()
    cli.exit_client('Quit: ' + reason)

@eventmgr.message('NICK', min_params=1)
def m_NICK(cli, ev_msg):
    new_nickname = ev_msg['params'][0]
    if new_nickname in cli.ctx.clients:
        cli.dump_numeric('433', [new_nickname, 'Nickname already in use'])
        return
    msg = RFC1459Message.from_data('NICK', source=cli.hostmask, params=[new_nickname])
    if cli.registered:
        if cli.nickname in cli.ctx.clients:
            cli.ctx.clients.pop(cli.nickname)
        cli.ctx.clients[new_nickname] = cli
        cli.sendto_common_peers(msg)
    cli.nickname = new_nickname
    cli.release_registration_lock(REGISTRATION_LOCK_NICK)

@eventmgr.message('USER', min_params=4)
def m_USER(cli, ev_msg):
    new_username = ev_msg['params'][0]
    new_realname = ev_msg['params'][3]
    cli.username = new_username
    cli.realname = new_realname
    cli.release_registration_lock(REGISTRATION_LOCK_USER)

@eventmgr.message('PING')
def m_PING(cli, ev_msg):
    reply = ev_msg['params'][0] if ev_msg['params'] else cli.ctx.conf.name
    msg = RFC1459Message.from_data('PONG', source=cli.ctx.conf.name, params=[reply])
    cli.dump_message(msg)

