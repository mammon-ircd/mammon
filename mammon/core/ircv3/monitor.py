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

from mammon.client import ClientProtocol
from mammon.server import eventmgr_core, eventmgr_rfc1459, get_context
from mammon.utility import validate_nick, validate_chan, CaseInsensitiveDict

monitored = CaseInsensitiveDict()

valid_metadata_subcommands = ('-', '+', 'c', 'l', 's')

@eventmgr_rfc1459.message('MONITOR', min_params=1)
def m_MONITOR(cli, ev_msg):
    command = ev_msg['params'][0].casefold()

    if command in valid_metadata_subcommands:
        # XXX - dumb hack until properties arrives
        if not hasattr(cli, 'monitoring'):
            cli.monitoring = []

        info = {
            'client': cli,
            'command': command,
        }

        limit = cli.ctx.conf.monitor.get('limit', None)
        if command == '+' and limit is not None:
            if len(cli.monitoring) + len(ev_msg['params'][1].split(',')) > limit:
                cli.dump_numeric('734', [cli.nickname, str(limit), ev_msg['params'][1], 'Monitor list is full'])
                return
        
        if command in '-+':
            targets = []
            for target in ev_msg['params'][1].split(','):
                if not validate_nick(target) and not validate_chan(target):
                    continue
                targets.append(target)

            info['targets'] = targets

        eventmgr_core.dispatch(' '.join(['monitor', command]), info)
    else:
        cli.dump_numeric(400, ['MONITOR', command, 'Unknown subcommand'])

@eventmgr_core.handler(('monitor -', 'monitor +'), priority=1)
def m_monitor_edit(info):
    for target in info['targets']:
        if target not in monitored:
            monitored[target] = []

        if info['command'] == '+':
            monitored[target].append(info['client'])
            info['client'].monitoring.append(target)

        elif info['command'] == '-':
            monitored[target].remove(info['client'])
            info['client'].monitoring.remove(target)

@eventmgr_core.handler('monitor c', priority=1)
def m_monitor_clear(info):
    for target in info['client'].monitoring:
        monitored[target].remove(info['client'])
    info['client'].monitoring = []

@eventmgr_core.handler('monitor l', priority=1, local_client='client')
def m_monitor_list(info):
    client = info['client']
    client.dump_numeric('732', [info['client'].nickname, ','.join(client.monitoring)])
    client.dump_numeric('733', [info['client'].nickname, 'End of MONITOR list'])

@eventmgr_core.handler('monitor s', priority=1, local_client='client')
def m_monitor_status(info):
    ctx = get_context()
    client = info['client']

    online = []
    offline = []

    for target in client.monitoring:
        if validate_nick(target):
            if target in ctx.clients:
                online.append(target)
            else:
                offline.append(target)

    if online:
        client.dump_numeric('730', [info['client'].nickname, ','.join(online)])
    if offline:
        client.dump_numeric('731', [info['client'].nickname, ','.join(offline)])

@eventmgr_core.handler('client connect')
def m_monitor_handle_connect(info):
    ctx = get_context()
    nick = info['client'].nickname
    for client in monitored.get(nick, []):
        if client.servername == ctx.conf.name:
            client.dump_numeric('730', [info['client'].nickname, info['client'].nickname])

@eventmgr_core.handler('client quit')
def m_monitor_handle_quit(info):
    ctx = get_context()
    nick = info['client'].nickname
    for client in monitored.get(nick, []):
        if client.servername == ctx.conf.name:
            client.dump_numeric('731', [info['client'].nickname, info['client'].nickname])
