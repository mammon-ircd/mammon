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
from mammon.server import eventmgr_rfc1459
from mammon.events import m_PRIVMSG
from mammon.capability import Capability

cap_away_notify = Capability('away-notify')

@eventmgr_rfc1459.message('AWAY')
def m_AWAY(cli, ev_msg):
    # away-notify propogation
    propogate = []
    for membership in cli.channels:
        for user in membership.channel.members:
            client = user.client
            if 'away-notify' in client.caps and client not in propogate and client != cli:
                propogate.append(client)

    # set away
    if len(ev_msg['params']):
        message = ev_msg['params'][0]
        cli.metadata['away'] = message

        cli.dump_numeric('306', ['You have been marked as being away'])

        params = [message]

    # unaway
    else:
        if 'away' in cli.metadata:
            del cli.metadata['away']

        cli.dump_numeric('305', ['You are no longer marked as being away'])

        params = None

    # away-notify propogate message
    msg = RFC1459Message.from_data('AWAY', source=cli.hostmask, params=params)
    for client in propogate:
        client.dump_message(msg)

@eventmgr_rfc1459.message('PRIVMSG')
def m_away_response(cli, ev_msg):
    target_name = ev_msg['params'][0]
    target = cli.ctx.clients.get(target_name, None)

    if target:
        awaymsg = target.metadata.get('away', None)
        if awaymsg:
            cli.dump_numeric('301', [target_name, awaymsg])
