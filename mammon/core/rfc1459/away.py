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
    message = None

    # set away
    if len(ev_msg['params']):
        message = ev_msg['params'][0]

    eventmgr_core.dispatch('client away', {
        'source': cli,
        'away': message
    })

@eventmgr_core.handler('client away', priority=1)
def m_away_process(info):
    cli = info['source']

    # away
    if info['away']:
        cli.metadata['away'] = info['away']
        cli.dump_numeric('306', ['You have been marked as being away'])

    # unaway
    elif 'away' in cli.metadata:
        cli.dump_numeric('305', ['You are no longer marked as being away'])
        del cli.metadata['away']

    # XXX - was already not away - do nothing and sink the event once supported
    else:
        pass

@eventmgr_core.handler('client away', priority=10)
def m_away_notify(info):
    cli = info['source']
    params = cli.metadata.get('away', None)
    if params:
        params = [params]
    msg = RFC1459Message.from_data('AWAY', source=cli, params=params)
    cli.sendto_common_peers(msg, exclude=[cli], cap='away-notify')

@eventmgr_core.handler('client message')
def m_away_response(info):
    awaymsg = info['target'].metadata.get('away', None)
    if awaymsg:
        info['source'].dump_numeric('301', [info['target_name'], awaymsg])
