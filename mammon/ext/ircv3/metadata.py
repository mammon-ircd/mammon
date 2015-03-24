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

import re

from mammon.server import eventmgr_core
from mammon.server import eventmgr_rfc1459
from mammon.capability import Capability

cap_metadata_notify = Capability('metadata-notify')

VALID_METADATA_KEY = re.compile(r'^[a-zA-Z0-9_\.\:]+$')

def is_valid_metadata_key(key):
    return bool(VALID_METADATA_KEY.search(key))

@eventmgr_rfc1459.message('METADATA', min_params=2)
def m_METADATA(cli, ev_msg):
    target_name, command = ev_msg['params'][:2]

    # get target
    permission_to_edit_target = False

    if target_name == '*':
        target = cli

        permission_to_edit_target = True
    else:
        target = cli.ctx.channels.get(target_name, None)
        if target is None:
            target = cli.ctx.clients.get(target_name, None)

            permission_to_edit_target = target == cli
            if not permission_to_edit_target:
                permission_to_edit_target = cli.role and 'metadata:edit' in cli.role.capabilities

    if target is None:
        cli.dump_numeric('765', [target_name, 'invalid metadata target'])
        return

    # list all metadata
    if command == 'LIST':
        returned_results = False

        for key, data in target.metadata.items():
            # check restricted keys
            if key in cli.ctx.conf.metadata.get('restricted_keys', []):
                if cli.role and key in cli.role.metakeys:
                    pass
                else:
                    continue

            # return key
            if not returned_results:
                returned_results = True

            args = [target_name, key, '*']
            if isinstance(target.metadata[key], str):
                args.append(data)
            cli.dump_numeric('761', args)

        if not returned_results:
            cli.dump_numeric('766', ['*', 'no matching keys'])
            return

    # list specific keys
    elif command == 'GET':
        if len(ev_msg['params']) > 2:
            keys = ev_msg['params'][2:]
        else:
            cli.dump_numeric('461', ['METADATA', 'Not enough parameters'])
            return

        for key in keys:
            if key in target.metadata:
                # XXX - to make sure user has privs to see this key
                #   probably through a  key -> [role]  map for restricted keys on server class
                #   and through channel ACL
                args = [target_name, key, '*']
                if isinstance(target.metadata[key], str):
                    args.append(target.metadata[key])
                cli.dump_numeric('761', args)
            elif not is_valid_metadata_key(key):
                cli.dump_numeric('767', [key, 'invalid metadata key'])
            else:
                cli.dump_numeric('766', [key, 'no matching keys'])

    # setting keys
    elif command == 'SET':
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
        if not permission_to_edit_target:
            cli.dump_numeric('769', [target_name, '*', 'permission denied'])
            return

        # check key is valid, and if we're using white/blacklists, check those too
        key_not_in_whitelist = cli.ctx.conf.metadata.get('whitelist', []) and key.lower() not in cli.ctx.conf.metadata.get('whitelist', [])
        key_in_blacklist = key.lower() in cli.ctx.conf.metadata.get('blacklist', [])

        if not is_valid_metadata_key(key) or key_not_in_whitelist or key_in_blacklist:
            cli.dump_numeric('767', [key, 'invalid metadata key'])
            return

        # check restricted keys
        key_restricted = False
        if key in cli.ctx.conf.metadata.get('restricted_keys', []):
            if cli.role and key in cli.role.metakeys:
                pass
            else:
                key_restricted = True

        # XXX - make sure user has privs to set this key through channel ACL

        if key_restricted:
            cli.dump_numeric('769', [target_name, key, 'permission denied'])
            return

        # set / unset key
        args = [target_name, key, '*']

        if value is None:
            try:
                target.user_set_metadata.remove(key.lower())
                del target.metadata[key]
            except KeyError:
                pass

        else:
            if key.lower() not in target.user_set_metadata and key.lower() not in cli.ctx.conf.metadata.get('restricted_keys', []):
                limit = cli.ctx.conf.metadata.get('limit', None)
                if limit is not None:
                    if len(target.user_set_metadata) + 1 > limit:
                        cli.dump_numeric('764', [target_name, 'metadata limit reached'])
                        return

                target.user_set_metadata.append(key.lower())
            target.metadata[key] = value
            args.append(value)

        cli.dump_numeric('761', args)

    # clearing all metadata
    elif command == 'CLEAR':
        # check user has permission for target
        if not permission_to_edit_target:
            cli.dump_numeric('769', [target_name, '*', 'permission denied'])
            return

        for key, data in dict(target.metadata).items():
            # XXX - to make sure user has perms to clear keys, channel ACL etc

            # we check keys here because even if a user is clearing their own METADATA,
            #   there may be admin / oper-only / server keys which should not be cleared
            if key in cli.ctx.conf.metadata.get('restricted_keys', []):
                if cli.role and key in cli.role.metakeys:
                    pass
                else:
                    continue

            # and clear the key
            try:
                target.metadata[key]
            except KeyError:
                pass
            target.user_set_metadata.remove(key.lower())
            cli.dump_numeric('761', [target_name, key, '*'])

    # almost everything returns this at the end
    cli.dump_numeric('762', ['end of metadata'])
