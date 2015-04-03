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
from mammon.server import eventmgr_core, eventmgr_rfc1459, get_context
from mammon.capability import Capability
from mammon.utility import UserHost

cap_away_notify = Capability('away-notify')

@eventmgr_rfc1459.message('AWAY')
def m_AWAY(cli, ev_msg):
    notify = True

    # set away
    if len(ev_msg['params']):
        message = ev_msg['params'][0]
        cli.metadata['away'] = message

        cli.dump_numeric('306', ['You have been marked as being away'])

        params = [message]

    # unaway
    else:
        if 'away' in cli.metadata:
            try:
                del cli.metadata['away']
            except KeyError:
                pass
        else:
            notify = False

        cli.dump_numeric('305', ['You are no longer marked as being away'])

    # away-notify propogate message
    if notify:
        eventmgr_core.dispatch('client away', cli)

@eventmgr_core.handler('client away')
def m_away_notify(cli):
    params = cli.metadata.get('away', None)
    if params:
        params = [params]
    msg = RFC1459Message.from_data('AWAY', source=cli.hostmask, params=params)
    cli.sendto_common_peers(msg, exclude=[cli], cap='away-notify')

@eventmgr_core.handler('client message')
def m_away_response(info):
    ctx = get_context()
    target = ctx.clients.get(info['target'], None)
    if not target:
        return

    awaymsg = target.metadata.get('away', None)
    if not awaymsg:
        return

    source = ctx.clients.get(UserHost(info['source']).nickname, None)
    if not source:
        return

    source.dump_numeric('301', [info['target'], awaymsg])
