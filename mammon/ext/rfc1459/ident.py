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

import asyncio

from mammon.client import client_registration_locks
from mammon.server import eventmgr_core

client_registration_locks.append('IDENT')

def do_ident_check(cli):
    """Handle looking up the client's ident as a coroutine."""
    cli.dump_notice('Checking Ident')

    try:
        local_address, local_port = cli.transport.get_extra_info('sockname')[:2]
        remote_address, remote_port = cli.transport.get_extra_info('peername')[:2]

        reader, writer = yield from asyncio.open_connection(cli.realaddr, 113, local_addr=(local_address, 0))

        writer.write(bytes(str(remote_port), 'ascii'))  # server port
        writer.write(b', ')
        writer.write(bytes(str(local_port), 'ascii'))  # client port
        writer.write(b'\r\n')

        # we only give it one shot, if the reply isn't good the first time we
        #   fail the auth entirely. this is the same as charyb
        line = yield from reader.readline()
        writer.close()

        # check
        args = line.split(b':')

        response_type = args[1].strip()

        if response_type == b'USERID':
            if b',' in args[2]:
                charset = args[2].split(b',')[1]
                charset = str(charset.strip(), 'utf8')
            else:
                # official default is "US-ASCII"
                charset = 'utf8'

            raw_ident = str(args[3].strip(), charset).lstrip('~^')

            ident = ''

            userlen = cli.ctx.conf.limits.get('user', None)
            if not isinstance(userlen, int):
                userlen = len(raw_ident)
            for i in range(userlen):
                if len(raw_ident) == 0 or raw_ident[0] == '@':
                    break

                if not raw_ident[0].isspace() and raw_ident[0] not in (':', '['):
                    ident += raw_ident[0]

                raw_ident = raw_ident[1:]

            if isinstance(userlen, int) and len(ident) > userlen:
                ident = ident[:userlen]

            cli.username = ident
            cli.dump_notice('Got Ident response')
            cli.release_registration_lock('IDENT')
            return
    except:
        pass

    cli.dump_notice('No Ident response')
    cli.release_registration_lock('IDENT')

@eventmgr_core.handler('client reglocked')
def m_ident_check(info):
    cli = info['client']
    asyncio.async(do_ident_check(cli))
