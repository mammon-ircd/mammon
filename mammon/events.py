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

from ircreactor.events import EventManager as EventManagerBase
from ircreactor.envelope import RFC1459Message

class EventManager(EventManagerBase):
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
