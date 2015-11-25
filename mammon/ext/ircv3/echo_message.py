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

from ircreactor.envelope import RFC1459Message

from mammon.server import eventmgr_core, get_context
from mammon.capability import Capability

cap_echo_message = Capability('echo-message')

@eventmgr_core.handler('client message', priority=10)
@eventmgr_core.handler('channel message', priority=10)
def m_privmsg_client(info):
    ctx = get_context()
    if ctx.conf.name == info['source'].servername and 'echo-message' in info['source'].caps:
        msg = RFC1459Message.from_data('PRIVMSG', source=info['source'].hostmask, params=[info['target_name'], info['message']])
        info['source'].dump_message(msg)
