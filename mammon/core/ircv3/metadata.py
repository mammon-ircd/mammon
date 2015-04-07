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

import string

from mammon.server import eventmgr_core, eventmgr_rfc1459
from mammon.capability import Capability
from mammon.utility import CaseInsensitiveList

# XXX - add to MONITOR system when implemented
# cap_metadata_notify = Capability('metadata-notify')

metadata_key_allowed_chars = string.ascii_letters + string.digits + '_.:'
metadata_key_allowed_chars_tbl = str.maketrans('', '', metadata_key_allowed_chars)

def validate_metadata_key(key_name):
    badchars = key_name.translate(metadata_key_allowed_chars_tbl)
    return badchars == ''

def metadata_GET(cli, ev_msg, target_name, target):
    if len(ev_msg['params']) > 2:
        keys = ev_msg['params'][2:]
    else:
        cli.dump_numeric('461', ['METADATA', 'Not enough parameters'])
        return

    restricted_keys = cli.ctx.conf.metadata.get('restricted_keys', [])

    for key in keys:
        if key in target.metadata:
            # check restricted keys
            visibility = '*'
            if key in restricted_keys:
                if cli.role and key in cli.role.metakeys_get:
                    visibility = 'server:restricted'
                else:
                    cli.dump_numeric('766', [key, 'no matching keys'])
                    continue

            # XXX - make sure user has privs to set this key through channel ACL

            args = [target_name, key, visibility]
            if isinstance(target.metadata[key], str):
                args.append(target.metadata[key])
            cli.dump_numeric('761', args)
        elif not validate_metadata_key(key):
            cli.dump_numeric('767', [key, 'invalid metadata key'])
        else:
            cli.dump_numeric('766', [key, 'no matching keys'])

def metadata_LIST(cli, ev_msg, target_name, target):
    restricted_keys = cli.ctx.conf.metadata.get('restricted_keys', [])

    for key, data in target.metadata.items():
        # check restricted keys
        visibility = '*'
        if key in restricted_keys:
            if cli.role and key in cli.role.metakeys_get:
                visibility = 'server:restricted'
            else:
                continue

        # return key
        args = [target_name, key, visibility]
        if isinstance(target.metadata[key], str):
            args.append(data)
        cli.dump_numeric('761', args)

    cli.dump_numeric('762', ['end of metadata'])

def metadata_SET(cli, ev_msg, target_name, target):
    if len(ev_msg['params']) > 2:
        key = ev_msg['params'][2]
        if len(ev_msg['params']) > 3:
            value = ev_msg['params'][3]
        else:
            value = None
    else:
        cli.dump_numeric('461', ['METADATA', 'Not enough parameters'])
        return

    # check user has permission for target
    if not cli.able_to_edit_metadata(target):
        cli.dump_numeric('769', [target_name, '*', 'permission denied'])
        return

    restricted_keys = cli.ctx.conf.metadata.get('restricted_keys', [])

    # check key is valid, and if we're using white/blacklists, check those too
    whitelist = cli.ctx.conf.metadata.get('whitelist', [])
    blacklist = cli.ctx.conf.metadata.get('blacklist', [])

    is_valid = False
    if validate_metadata_key(key):
        if key not in blacklist:
            if key in whitelist or not whitelist or key in restricted_keys:
                is_valid = True

    if not is_valid:
        cli.dump_numeric('767', [key, 'invalid metadata key'])
        return

    # check restricted keys
    key_restricted = False
    visibility = '*'
    if key in restricted_keys:
        if cli.role and key in cli.role.metakeys_set:
            visibility = 'server:restricted'
        else:
            key_restricted = True

    # XXX - make sure user has privs to set this key through channel ACL

    if key_restricted:
        cli.dump_numeric('769', [target_name, key, 'permission denied'])
        return

    # set / unset key
    args = [target_name, key, visibility]

    if value is None:
        try:
            target.user_set_metadata.remove(key)
            del target.metadata[key]
        except KeyError:
            pass

    else:
        # if setting a new, non-restricted key, take metadata limits into account
        if key not in target.user_set_metadata and key not in restricted_keys:
            limit = cli.ctx.conf.metadata.get('limit', None)
            if limit is not None:
                if len(target.user_set_metadata) + 1 > limit:
                    cli.dump_numeric('764', [target_name, 'metadata limit reached'])
                    return

            target.user_set_metadata.append(key)
        target.metadata[key] = value
        args.append(value)

    cli.dump_numeric('761', args)

    cli.dump_numeric('762', ['end of metadata'])

def metadata_CLEAR(cli, ev_msg, target_name, target):
    # check user has permission for target
    if not cli.able_to_edit_metadata(target):
        cli.dump_numeric('769', [target_name, '*', 'permission denied'])
        return

    restricted_keys = cli.ctx.conf.metadata.get('restricted_keys', [])
    if cli.role:
        viewable_keys = restricted_keys + cli.role.metakeys_get + cli.role.metakeys_set
    else:
        viewable_keys = []

    for key, data in dict(target.metadata).items():
        # XXX - make sure user has perms to clear keys via channel ACL

        # we check keys here because even if a user is clearing their own METADATA,
        #   there may be admin / oper-only / server keys which should not be cleared
        visibility = '*'
        if key in restricted_keys:
            # user cannot see key at all, this is likely a server / oper-only key
            #   so we're not going to even tell them it exists
            if key not in viewable_keys:
                continue

            elif cli.role and key in cli.role.metakeys_set:
                visibility = 'server:restricted'

            # if they don't have permission to edit this specific key, just ignore it
            #   maybe the spec should say throw an ERR_KEYNOPERMISSION here?
            else:
                continue

        # and clear the key
        try:
            target.metadata[key]
        except KeyError:
            pass
        target.user_set_metadata.remove(key)
        cli.dump_numeric('761', [target_name, key, visibility])

    cli.dump_numeric('762', ['end of metadata'])

metadata_subcommands = {
    'get': metadata_GET,
    'list': metadata_LIST,
    'set': metadata_SET,
    'clear': metadata_CLEAR,
}

@eventmgr_rfc1459.message('METADATA', min_params=2)
def m_METADATA(cli, ev_msg):
    target_name, command = ev_msg['params'][:2]

    # get target
    if target_name == '*':
        target = cli
    else:
        target = cli.ctx.channels.get(target_name, None)
        if target is None:
            target = cli.ctx.clients.get(target_name, None)

    if target is None:
        cli.dump_numeric('765', [target_name, 'invalid metadata target'])
        return

    command = command.casefold()

    if command in metadata_subcommands:
        metadata_subcommands[command](cli, ev_msg, target_name, target)
    else:
        cli.dump_numeric(400, ['METADATA', command, 'Unknown subcommand'])
