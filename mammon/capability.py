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

from mammon.utility import CaseInsensitiveDict
from mammon.events import eventmgr_rfc1459
from ircreactor.envelope import RFC1459Message

caplist = CaseInsensitiveDict()

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

Capability('cap-notify')

def m_CAP_LS(cli, ev_msg):
    is_ircv3_2 = len(ev_msg['params']) > 1 and int(ev_msg['params'][1]) > 301
    if is_ircv3_2:
        cli.caps['cap-notify'] = caplist['cap-notify']

    l = list()
    for cap in caplist.values():
        l.append(cap.atom(is_ircv3_2))
        if len(l) > 8:
            cli.dump_numeric('CAP', ['LS', '*', ' '.join(l)])
            l = list()

    if l:
        cli.dump_numeric('CAP', ['LS', ' '.join(l)])

def m_CAP_LIST(cli, ev_msg):
    l = list()
    for cap in cli.caps.values():
        l.append(cap.name)
        if len(l) > 8:
            cli.dump_numeric('CAP', ['LIST', '*', ' '.join(l)])
            l = list()

    if l:
        cli.dump_numeric('CAP', ['LIST', ' '.join(l)])

def m_CAP_CLEAR(cli, ev_msg):
    to_remove = list(filter(lambda x: not x.sticky, cli.caps.values()))

    changelist = list()
    while to_remove:
        cap = to_remove.pop(0)
        cap = cli.caps.pop(cap.name)
        changelist.append('-' + cap.name)
        if len(changelist) > 8:
            cli.dump_numeric('CAP', ['ACK', ' '.join(changelist)])
            changelist = list()

    if changelist:
        cli.dump_numeric('CAP', ['ACK', ' '.join(changelist)])

def m_CAP_END(cli, ev_msg):
    cli.release_registration_lock('CAP')

# XXX - we add a trailing space for mIRC.  remove it once mIRC fixes their client.
def m_CAP_REQ(cli, ev_msg):
    cap_add = []
    cap_del = []
    args = ev_msg['params'][1]

    def dump_NAK(cli):
        cli.dump_numeric('CAP', ['NAK', args + ' '])

    for arg in args.split():
        negate = arg[0] == '-'

        if negate:
            arg = arg[1:]

        if arg not in caplist:
            dump_NAK(cli)
            return

        if negate:
            if arg not in cli.caps:
                dump_NAK(cli)
                return
            cap_del.append(arg)
            continue

        if arg in cli.caps:
            dump_NAK(cli)
            return

        cap_add.append(arg)

    cli.dump_numeric('CAP', ['ACK', ' '.join(cap_add) + ' -'.join(cap_del) + ' '])

    # we accepted the changeset, so apply it
    info = {
        'client': cli,
        'caps': cap_add,
    }
    eventmgr_core.dispatch('cap add', info)

    info = {
        'client': cli,
        'caps': cap_del,
    }
    eventmgr_core.dispatch('cap del', info)

@eventmgr_core.handler('cap add', priority=1)
def m_cap_add(info):
    cli = info['client']

    for cap in info['caps']:
        cli.caps[cap] = caplist[cap]

@eventmgr_core.handler('cap del', priority=1)
def m_cap_del(info):
    cli = info['client']

    for cap in info['caps']:
        cli.caps.pop(cap)

# XXX: implement CAP ACK for real if it becomes necessary (nothing uses it)
def m_CAP_ACK(cli, ev_msg):
    cap_add = []
    cap_del = []
    args = ev_msg['params'][1]

    def dump_NAK(cli):
        cli.dump_numeric('CAP', ['NAK', args + ' '])

    # sanity check the ACK, send NAK if it makes no sense
    for arg in args.split():
        negate = arg[0] == '-'

        if negate:
            arg = arg[1:]

        if arg not in caplist:
            dump_NAK(cli)
            return

        if negate:
            cap = caplist[arg]
            if cap.sticky:
                dump_NAK(cli)
                return
            continue

        if arg not in cli.caps:
            dump_NAK(cli)
            return

    # XXX: make the CAP change atomic someday (code would go here)
    cli.dump_numeric('CAP', ['ACK', args + ' '])

cap_cmds = {
    'CLEAR': m_CAP_CLEAR,
    'LS': m_CAP_LS,
    'LIST': m_CAP_LIST,
    'END': m_CAP_END,
    'REQ': m_CAP_REQ,
    'ACK': m_CAP_ACK,
}
cap_cmds = CaseInsensitiveDict(**cap_cmds)

@eventmgr_rfc1459.message('CAP', min_params=1, allow_unregistered=True)
def m_CAP(cli, ev_msg):
    subcmd = ev_msg['params'][0]

    if subcmd not in cap_cmds:
        cli.dump_numeric('410', [subcmd, 'Invalid CAP subcommand'])
        return

    if subcmd != 'END':
        cli.push_registration_lock('CAP')

    cap_cmds[subcmd](cli, ev_msg)
