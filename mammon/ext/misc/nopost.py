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

from mammon.server import eventmgr_rfc1459

@eventmgr_rfc1459.message('POST', allow_unregistered=True)
def m_POST(cli, ev_msg):
    cli.quit('HTTP POST command was received from IRC connection')

@eventmgr_rfc1459.message('PUT', allow_unregistered=True)
def m_PUT(cli, ev_msg):
    cli.quit('HTTP PUT command was received from IRC connection')

@eventmgr_rfc1459.message('PATCH', allow_unregistered=True)
def m_PATCH(cli, ev_msg):
    cli.quit('HTTP PATCH command was received from IRC connection')

@eventmgr_rfc1459.message('STATUS', allow_unregistered=True)
def m_STATUS(cli, ev_msg):
    cli.quit('HTTP STATUS command was received from IRC connection')
