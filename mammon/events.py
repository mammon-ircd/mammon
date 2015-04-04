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

import logging
from functools import wraps

from ircreactor.events import EventManager as EventManagerBase

class EventManager(EventManagerBase):
    """
    An EventManager acts as a hub for consuming intermediate-representation messages and acting on them.
    It distributes events to 0 or more subscribers.

    Depending on layer, there are multiple event managers.
    """
    def __init__(self):
        super(EventManager, self).__init__()

    def connect(self, event):
        def wrapped_fn(func):
            self.register(event, func)
            return func
        return wrapped_fn

    def handler(self, messages, priority=10):
        if not isinstance(messages, (list, tuple)):
            messages = [messages]
        def parent_fn(func):
            for message in messages:
                self.register(message, func, priority=priority)
            return func
        return parent_fn

class RFC1459EventManager(EventManager):
    """A specialized event manager for RFC1459 commands.
    If an EventObject does not exist, then we send numeric 421."""
    def __init__(self):
        super(RFC1459EventManager, self).__init__()

    def dispatch(self, event, ev_msg):
        """Dispatch an event.
               event: name of the event (str)
               ev_msg: non-optional arguments dictionary.
           Side effects: None"""
        eo = self.events.get(event, None)
        if not eo:
            return self.handle_unknown(ev_msg)
        eo.dispatch(ev_msg)

    def handle_unknown(self, ev_msg):
        """Handle an unknown event.
              ev_msg: non-optional arguments dictionary.
           Side effects: None"""
        cli = ev_msg['client']
        cli.dump_numeric('421', [ev_msg['verb'], 'Unknown command'])

    def message(self, verb, min_params=0, update_idle=False, priority=10, allow_unregistered=False):
        def parent_fn(func):
            @wraps(func)
            def child_fn(ev_msg):
                cli = ev_msg['client']
                if not allow_unregistered and not cli.registered:
                    cli.dump_numeric('451', ['You have not registered'])
                    return
                if len(ev_msg['params']) < min_params:
                    cli.dump_numeric('461', [ev_msg['verb'], 'Not enough parameters'])
                    return
                if update_idle:
                    cli.update_idle()
                return func(cli, ev_msg)
            self.register('rfc1459 message ' + verb, child_fn, priority=priority)
            return child_fn
        return parent_fn

eventmgr_core = EventManager()
eventmgr_rfc1459 = RFC1459EventManager()
