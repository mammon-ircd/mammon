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

# XXX
REGISTRATION_LOCK_NICK = 0x1
REGISTRATION_LOCK_USER = 0x2

import logging
from functools import wraps

from ircreactor.events import EventManager as EventManagerBase
from ircreactor.envelope import RFC1459Message

from . import __credits__, __version__
from .utility import validate_nick, validate_chan

class EventManager(EventManagerBase):
    """
    An EventManager acts as a hub for consuming intermediate-representation messages and acting on them.
    It distributes events to 0 or more subscribers.

    Depending on layer, there are multiple event managers.
    """
    def __init__(self):
        super(EventManager, self).__init__()

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
        msg = RFC1459Message.from_data('421', source=cli.ctx.conf.name, params=[cli.nickname, ev_msg['verb'], 'Unknown command'])
        cli.dump_message(msg)

    def connect(self, event):
        def wrapped_fn(func):
            self.register(event, func)
            return func
        return wrapped_fn

    def message(self, verb, min_params=0, update_idle=False):
        def parent_fn(func):
            @wraps(func)
            def child_fn(ev_msg):
                cli = ev_msg['client']
                if len(ev_msg['params']) < min_params:
                    msg = RFC1459Message.from_data('461', source=cli.ctx.conf.name, params=[cli.nickname, ev_msg['verb'], 'Not enough parameters'])
                    cli.dump_message(msg)
                    return
                if update_idle:
                    cli.update_idle()
                return func(cli, ev_msg)
            self.register('rfc1459 message ' + verb, child_fn)
            return child_fn
        return parent_fn

eventmgr_core = EventManager()
eventmgr_rfc1459 = EventManager()

# - - - BUILTIN EVENTS - - -

@eventmgr_rfc1459.message('QUIT')
def m_QUIT(cli, ev_msg):
    reason = ev_msg['params'][0] if ev_msg['params'] else str()
    cli.exit_client('Quit: ' + reason)

@eventmgr_rfc1459.message('NICK', min_params=1)
def m_NICK(cli, ev_msg):
    new_nickname = ev_msg['params'][0]
    if not validate_nick(new_nickname):
        cli.dump_numeric('432', [new_nickname, 'Erroneous nickname'])
        return
    if new_nickname in cli.ctx.clients:
        cli.dump_numeric('433', [new_nickname, 'Nickname already in use'])
        return
    msg = RFC1459Message.from_data('NICK', source=cli.hostmask, params=[new_nickname])
    if cli.registered:
        if cli.nickname in cli.ctx.clients:
            cli.ctx.clients.pop(cli.nickname)
        cli.ctx.clients[new_nickname] = cli
        cli.sendto_common_peers(msg)
    cli.nickname = new_nickname
    cli.release_registration_lock(REGISTRATION_LOCK_NICK)

@eventmgr_rfc1459.message('USER', min_params=4)
def m_USER(cli, ev_msg):
    new_username = ev_msg['params'][0]
    new_realname = ev_msg['params'][3]
    cli.username = new_username
    cli.realname = new_realname
    cli.release_registration_lock(REGISTRATION_LOCK_USER)

@eventmgr_rfc1459.message('PING')
def m_PING(cli, ev_msg):
    reply = ev_msg['params'][0] if ev_msg['params'] else cli.ctx.conf.name
    msg = RFC1459Message.from_data('PONG', source=cli.ctx.conf.name, params=[reply])
    cli.dump_message(msg)

@eventmgr_rfc1459.message('PONG', min_params=1)
def m_PONG(cli, ev_msg):
    if cli.ping_cookie and int(ev_msg['params'][0]) != cli.ping_cookie:
        return
    cli.last_pong = cli.ctx.eventloop.time()

@eventmgr_rfc1459.message('INFO')
def m_INFO(cli, ev_msg):
    lines = __credits__.splitlines()
    for line in lines:
        cli.dump_numeric('371', [line])
    cli.dump_numeric('374', ['End of /INFO list.'])

@eventmgr_rfc1459.message('VERSION')
def m_VERSION(cli, ev_msg):
    cli.dump_numeric('351', ['mammon-' + str(__version__), cli.ctx.conf.name])
    cli.dump_isupport()

@eventmgr_rfc1459.message('PRIVMSG', min_params=2, update_idle=True)
def m_PRIVMSG(cli, ev_msg):
    target = ev_msg['params'][0]
    message = ev_msg['params'][1]

    if target[0] != '#':
        cli_tg = cli.ctx.clients.get(target, None)
        if not cli_tg:
            cli.dump_numeric('401', [target, 'No such nick/channel'])
            return
        msg = RFC1459Message.from_data('PRIVMSG', source=cli.hostmask, params=[cli_tg.nickname, message])
        cli_tg.dump_message(msg)
        return

    ch = cli.ctx.chmgr.get(target)
    if not ch:
        cli.dump_numeric('401', [target, 'No such nick/channel'])
        return

    if not ch.can_send(cli):
        cli.dump_numeric('404', [ch.name, 'Cannot send to channel'])
        return

    msg = RFC1459Message.from_data('PRIVMSG', source=cli.hostmask, params=[ch.name, message])
    ch.dump_message(msg, exclusion_list=[cli])

@eventmgr_rfc1459.message('NOTICE', min_params=2)
def m_NOTICE(cli, ev_msg):
    target = ev_msg['params'][0]
    message = ev_msg['params'][1]

    if target[0] != '#':
        cli_tg = cli.ctx.clients.get(target, None)
        if not cli_tg:
            return
        msg = RFC1459Message.from_data('NOTICE', source=cli.hostmask, params=[cli_tg.nickname, message])
        cli_tg.dump_message(msg)
        return

    ch = cli.ctx.chmgr.get(target)
    if not ch or not ch.can_send(cli):
        return

    msg = RFC1459Message.from_data('NOTICE', source=cli.hostmask, params=[ch.name, message])
    ch.dump_message(msg, exclusion_list=[cli])

@eventmgr_rfc1459.message('MOTD')
def m_MOTD(cli, ev_msg):
    if cli.ctx.conf.motd:
        cli.dump_numeric('375', ['- ' + cli.ctx.conf.name + ' Message of the Day -'])
        for i in cli.ctx.conf.motd:
            cli.dump_numeric('372', ['- ' + i])
        cli.dump_numeric('376', ['End of /MOTD command.'])
    else:
        cli.dump_numeric('422', ['MOTD File is missing'])

@eventmgr_rfc1459.message('MODE', min_params=1)
def m_MODE(cli, ev_msg):
    if ev_msg['params'][0] == cli.nickname:
        if len(ev_msg['params']) == 1:
            cli.dump_numeric('221', [cli.legacy_modes])
            return
        cli.set_legacy_modes(ev_msg['params'][1])
        return
    elif ev_msg['params'][0][0] != '#':
        cli.dump_numeric('502', ["Can't change mode for other users"])
        return

    # XXX - channels not implemented

@eventmgr_rfc1459.message('ISON', min_params=1)
def m_ISON(cli, ev_msg):
    matches = []

    # charybdis implements it roughly this way.  rfc1459 is ambiguous, so we will
    # use charybdis's implementation.
    for chunk in ev_msg['params']:
        for subchunk in chunk.split():
            if subchunk in cli.ctx.clients:
                matches.append(subchunk)

    # ircII derivatives needs a trailing space, ugh.
    # unfortunately BitchX is ircv3.1 compliant so we actually have to care about this
    cli.dump_numeric('303', [' '.join(matches) + ' '])

# WHO 0 o
# WHO #channel
@eventmgr_rfc1459.message('WHO', min_params=1)
def m_WHO(cli, ev_msg):
    oper_query = False
    if len(ev_msg['params']) > 1:
        oper_query = 'o' in ev_msg['params'][1]

    def do_single_who(cli, target, status=None):
        if oper_query and not target.operator:
            return
        if not status:
            status = target.status
        cli.dump_numeric('352', [target.username, target.hostname, target.servername, target.nickname, status, '0 ' + target.realname])

    target = ev_msg['params'][0]
    if target[0] == '#':
        chan = cli.ctx.chmgr.get(target)
        if chan:
            [do_single_who(cli, i.client, i.who_status) for i in chan.members]
    else:
        u = cli.ctx.clients.get(target, None)
        if u:
            do_single_who(cli, u)

    cli.dump_numeric('315', ['End of /WHO list.'])

# WHOIS nickname
@eventmgr_rfc1459.message('WHOIS', min_params=1)
def m_WHOIS(cli, ev_msg):
    target = ev_msg['params'][0]

    cli_tg = cli.ctx.clients.get(target, None)
    if not cli_tg:
        cli.dump_numeric('401', [target, 'No such nick/channel'])
        return

    channels = tuple(filter(lambda x: 'secret' not in x.channel.props or x.channel.has_member(cli), cli_tg.channels))

    cli.dump_numeric('311', [cli_tg.nickname, cli_tg.username, cli_tg.hostname, '*', cli_tg.realname])
    if channels:
        cli.dump_numeric('319', [cli_tg.nickname, ' '.join([x.channel_name for x in channels]) + ' '])
    cli.dump_numeric('312', [cli_tg.nickname, cli.ctx.conf.name, cli.ctx.conf.description])
    if cli_tg.operator:
        cli.dump_numeric('313', [cli_tg.nickname, 'is an IRC operator.'])
    if cli_tg.account:
        cli.dump_numeric('330', [cli_tg.nickname, cli_tg.account.name, 'is logged in as'])
    cli.dump_numeric('317', [cli_tg.nickname, cli_tg.idle_time, cli_tg.registration_ts, 'seconds idle, signon time'])
    cli.dump_numeric('319', [cli_tg.nickname, 'End of /WHOIS list.'])

# WHOWAS nickname
@eventmgr_rfc1459.message('WHOWAS', min_params=1)
def m_WHOWAS(cli, ev_msg):
    target = ev_msg['params'][0]

    whowas_entry = cli.ctx.client_history.get(target, None)
    if not cli_tg:
        cli.dump_numeric('406', [target, 'There was no such nickname'])
        return

    cli.dump_numeric('314', [whowas_entry.nickname, whowas_entry.username, whowas_entry.hostname, '*', whowas_entry.realname])
    cli.dump_numeric('312', [whowas_entry.nickname, cli.ctx.conf.name, cli.ctx.conf.description])
    if whowas_entry.account:
        cli.dump_numeric('330', [whowas_entry.nickname, whowas_entry.account, 'was logged in as'])
    cli.dump_numeric('369', [whowas_entry.nickname, 'End of WHOWAS'])
