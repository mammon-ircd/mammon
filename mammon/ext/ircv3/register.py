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

from email.mime.text import MIMEText
from subprocess import Popen, PIPE

supported_cred_types = ['passphrase']
supported_cb_types = ['*', 'mailto']

global supported_cred_types
global supported_cb_types

def generate_auth_code():
    from passlib.utils import generate_password
    code = generate_password(size=15)
    return code

@eventmgr_core.handler('server start')
def m_server_start(info):
    ctx = info['server']

    if ctx.conf.register['callbacks']:
        callbacks = ','.join(ctx.conf.register['callbacks'])
    else:
        callbacks = ''

    global supported_cred_types
    global supported_cb_types

    if not ctx.hashing.enabled:
        ctx.logger.info('REG disabled because hashing is not available')
        return
    if len(supported_cred_types) == 0:
        ctx.logger.info('REG disabled because no mechanisms are available')
        return

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
            return

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
            cli.dump_numeric('461', [ev_msg['verb'], 'Not enough parameters'])
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
    elif subcmd == 'verify':
        account = params.pop(0).casefold()

        account_info = cli.ctx.data.get('account.{}'.format(account), None)

        if account_info:
            if account_info['verified']:
                cli.dump_numeric('924', [account, 'Account already verified'])
                return

            auth_code = params.pop(0)

            if auth_code == account_info['auth_code']:
                account_info['verified'] = True
                del account_info['auth_code']
                cli.ctx.data.put('account.{}'.format(account), account_info)

                cli.dump_numeric('923', [account, 'Account verification successful'])
                cli.account = account
                cli.dump_numeric('900', [cli.hostmask, account,
                                         'You are now logged in as {}'.format(account)])
                cli.dump_numeric('903', ['Authentication successful'])
            else:
                cli.dump_numeric('925', [account, 'Invalid verification code'])
        else:
            cli.dump_numeric('400', ['REG', 'VERIFY', 'Account does not exist'])
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
        'account': info['account'],
        'credentials': {
            'passphrase': cli.ctx.hashing.encrypt(info['credential']),
        },
        'registered': cli.ctx.current_ts,
        'registered_by': cli.hostmask,
        'verified': True,
    })

    cli.dump_numeric('920', params=[info['account'], 'Account created'])
    cli.account = info['account']
    cli.dump_numeric('900', params=[cli.hostmask, info['account'],
                                    'You are now logged in as {}'.format(info['account'])])
    cli.dump_numeric('903', params=['Authentication successful'])

@eventmgr_core.handler('reg callback mailto')
def m_reg_create_empty(info):
    cli = info['source']

    auth_code = generate_auth_code()

    cli.ctx.data.put('account.{}'.format(info['account']), {
        'account': info['account'],
        'credentials': {
            'passphrase': cli.ctx.hashing.encrypt(info['credential']),
        },
        'registered': cli.ctx.current_ts,
        'registered_by': cli.hostmask,
        'verified': False,
        'auth_code': auth_code,
    })

    conf = cli.ctx.conf.register['callbacks']['mailto']

    # assemble email
    message = conf['verify_message'].format(**{
        'account': info['account'],
        'auth_code': auth_code,
        'network_name': cli.ctx.conf.server['network'],
    })

    assembled_message = MIMEText(message)

    assembled_message['From'] = conf['from']
    assembled_message['To'] = info['callback']
    assembled_message['Subject'] = conf['verify_message_subject'].format(**{
        'account': info['account'],
        'network_name': cli.ctx.conf.server['network'],
    })

    # send message
    p = Popen([conf['sendmail'], '-t', '-oi'], stdin=PIPE)
    p.communicate(assembled_message.as_bytes())

    cli.dump_numeric('920', params=[info['account'], 'Account created'])
    cli.dump_numeric('927', params=[info['account'], info['callback'], 'A verification code was sent'])
