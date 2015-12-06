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

from mammon.events import eventmgr_core, eventmgr_rfc1459
from mammon.isupport import get_isupport

supported_cred_types = ['passphrase']
supported_cb_types = ['*', 'mailto']

@eventmgr_core.handler('server start')
def m_server_start(info):
    ctx = info['server']

    if ctx.conf.register['callbacks']:
        callbacks = ','.join(ctx.conf.register['callbacks'])
    else:
        callbacks = ''

    isupport_tokens = get_isupport()
    isupport_tokens['REGCOMMANDS'] = 'CREATE,VERIFY'
    isupport_tokens['REGCALLBACKS'] = callbacks
    isupport_tokens['REGCREDTYPES'] = ','.join(supported_cred_types)

@eventmgr_rfc1459.message('REG', min_params=3)
def m_REG(cli, ev_msg):
    params = list(ev_msg['params'])
    subcmd = params.pop(0).casefold()

    if subcmd == 'create':
        account = params.pop(0).casefold()

        if 'account.{}'.format(account) in cli.ctx.data:
            cli.dump_numeric('921', params=[account, 'Account already exists'])

        callback = params.pop(0).casefold()
        if callback == '*':
            cb_namespace = '*'
            callback = None,
        elif ':' in callback:
            cb_namespace, callback = callback.split(':', 1)
        else:
            cb_namespace = 'mailto'

        if cb_namespace not in supported_cb_types:
            cli.dump_numeric('929', params=[account, cb_namespace, 'Callback token is invalid'])
            return

        if len(params) > 1:
            cred_type, credential = params[:2]
        elif len(params) == 1:
            cred_type = 'passphrase'
            credential = params.pop(0)
        else:
            # not enough params
            return

        if cred_type not in supported_cred_types:
            cli.dump_numeric('928', params=[account, cred_type, 'Credential type is invalid'])
            return

        eventmgr_core.dispatch('reg callback {}'.format(cb_namespace), {
            'source': cli,
            'account': account,
            'callback': callback,
            'cb_namespace': cb_namespace,
            'cred_type': cred_type,
            'credential': credential,
        })
    else:
        cli.dump_numeric('400', ['REG', ev_msg['params'][0], 'Unknown subcommand'])

@eventmgr_core.handler('reg callback *')
def m_reg_create_empty(info):
    cli = info['source']

    # only allow empty callback when no other callbacks exist
    if cli.ctx.conf.register['callbacks']:
        cli.dump_numeric('929', params=[info['account'], '*', 'Callback token is invalid'])
        return

    cli.ctx.data.put('account.{}'.format(info['account']), {
        'source': cli.hostmask,
        'account': info['account'],
        'registered': cli.ctx.current_ts,
        'credentials': {
            'passphrase': info['credential'],
        },
    })

    cli.dump_numeric('920', params=[info['account'], 'Account created'])
    cli.account = info['account']
    cli.dump_numeric('900', params=[cli.hostmask, info['account'],
                                    'You are now logged in as {}'.format(info['account'])])
    cli.dump_numeric('903', params=['Authentication successful'])
