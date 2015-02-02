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

from mammon.events import eventmgr_rfc1459
from ircreactor.envelope import RFC1459Message

caplist = {}

class Capability(object):
    """A capability object describes a capability token offered by
    IRCv3.2 capability negotiation.  It consists of a key and an
    optional value argument.  If we're negotiating as a IRCv3.1 client,
    then we do not show the value tokens."""
    def __init__(self, name, value=None, sticky=False):
        global caplist

        self.name = name
        self.value = value
        self.sticky = sticky
        caplist[self.name] = self

    def atom(self, ircv3_2=False):
        "Returns the CAP atom, based on what revision of CAP is requested."
        if not ircv3_2:
            return self.name
        pstr = self.name
        if self.value:
            pstr += '=' + self.value
        return pstr

Capability('server-time')
Capability('cap-notify')

cap_cmds = {}

@eventmgr_rfc1459.message('CAP', min_params=1)
def m_CAP(cli, ev_msg):
    subcmd = ev_msg['params'][0]

    if subcmd not in cap_cmds:
        cli.dump_numeric('410', [subcmd, 'Invalid CAP subcommand'])
        return

    cap_cmds[subcmd](cli, ev_msg)
