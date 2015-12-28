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

from mammon.server import eventmgr_core, eventmgr_rfc1459, get_context
from mammon.utility import validate_nick, CaseInsensitiveDict

monitored = CaseInsensitiveDict()

valid_metadata_subcommands = ('-', '+', 'c', 'l', 's')

@eventmgr_rfc1459.message('MONITOR', min_params=1)
def m_MONITOR(cli, ev_msg):
    command = ev_msg['params'][0].casefold()

    if command in valid_metadata_subcommands:
        info = {
            'client': cli,
            'command': command,
        }

        limit = cli.ctx.conf.monitor.get('limit', None)
        if command == '+' and limit is not None:
            if len([c for c in cli.monitoring if validate_nick(c)]) + len(ev_msg['params'][1].split(',')) > limit:
                cli.dump_numeric('734', [str(limit), ev_msg['params'][1], 'Monitor list is full'])
                return

        if command in '-+':
            targets = []
            for target in ev_msg['params'][1].split(','):
                if not validate_nick(target):
                    continue
                targets.append(target)

            info['targets'] = targets

        eventmgr_core.dispatch(' '.join(['monitor', command]), info)
    else:
        cli.dump_numeric('400', ['MONITOR', command, 'Unknown subcommand'])

@eventmgr_core.handler(('monitor -', 'monitor +'), priority=1)
def m_monitor_edit(info):
    ctx = get_context()
    cli = info['client']
    if info['command'] == '+':
        online = []
        offline = []

    for target in info['targets']:
        if target not in monitored:
            monitored[target] = set()

        if info['command'] == '+':
            monitored[target].add(cli)
            cli.monitoring.add(target)

            if target in ctx.clients:
                online.append(target)
            else:
                offline.append(target)

        elif info['command'] == '-':
            monitored[target].discard(cli)
            cli.monitoring.discard(target)

    if info['command'] == '+':
        if online:
            cli.dump_numeric('730', [','.join(online)])
        if offline:
            cli.dump_numeric('731', [','.join(offline)])

@eventmgr_core.handler('monitor c', priority=1)
def m_monitor_clear(info):
    cli = info['client']
    for target in cli.monitoring:
        if validate_nick(target):
            monitored[target].remove(cli)
    cli.monitoring = [c for c in cli.monitoring if not validate_nick(c)]

@eventmgr_core.handler('monitor l', priority=1, local_client='client')
def m_monitor_list(info):
    cli = info['client']
    cli.dump_numeric('732', [','.join([c for c in cli.monitoring if validate_nick(c)])])
    cli.dump_numeric('733', ['End of MONITOR list'])

@eventmgr_core.handler('monitor s', priority=1, local_client='client')
def m_monitor_status(info):
    ctx = get_context()
    cli = info['client']

    online = []
    offline = []

    for target in cli.monitoring:
        if validate_nick(target):
            if target in ctx.clients:
                online.append(target)
            else:
                offline.append(target)

    if online:
        cli.dump_numeric('730', [','.join(online)])
    if offline:
        cli.dump_numeric('731', [','.join(offline)])

@eventmgr_core.handler('client connect')
def m_monitor_handle_connect(info):
    ctx = get_context()
    nick = info['client'].nickname
    for client in monitored.get(nick, []):
        if client.servername == ctx.conf.name:
            client.dump_numeric('730', [nick])

@eventmgr_core.handler('client quit')
def m_monitor_handle_quit(info):
    ctx = get_context()
    nick = info['client'].nickname
    for client in monitored.get(nick, []):
        if client.servername == ctx.conf.name:
            client.dump_numeric('731', [nick])
