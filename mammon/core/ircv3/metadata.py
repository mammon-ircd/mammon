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

from mammon.server import eventmgr_core, eventmgr_rfc1459, get_context
from mammon.capability import Capability
from mammon.utility import CaseInsensitiveDict, CaseInsensitiveList

from . import monitor

cap_metadata_notify = Capability('metadata-notify')

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

    # if setting a new, non-restricted key, take metadata limits into account
    # NOTE: we check these here instead of in dispatch handler because we should only
    #   throw valid events, makes more sense to check it before we send the event
    if value:
        if key not in target.user_set_metadata and key not in restricted_keys:
            limit = cli.ctx.conf.metadata.get('limit', None)
            if limit is not None:
                if len(target.user_set_metadata) + 1 > limit:
                    cli.dump_numeric('764', [target_name, 'metadata limit reached'])
                    return

    # throw change
    info = {
        'key': key,
        'value': value,
        'source': cli,
        'target': target,
        'target_name': target_name,
        'visibility': visibility,
    }
    eventmgr_core.dispatch('metadata set', info)

def metadata_CLEAR(cli, ev_msg, target_name, target):
    # check user has permission for target
    if not cli.able_to_edit_metadata(target):
        cli.dump_numeric('769', [target_name, '*', 'permission denied'])
        return

    restricted_keys = cli.ctx.conf.metadata.get('restricted_keys', [])
    viewable_keys = CaseInsensitiveList()
    if cli.role:
        viewable_keys += restricted_keys + cli.role.metakeys_get + cli.role.metakeys_set

    key_list = {}

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
            else:
                continue

        key_list[key] = {
            'visibility': visibility,
        }

    # throw change
    info = {
        'source': cli,
        'target': target,
        'target_name': target_name,
        'keys': key_list,
    }
    eventmgr_core.dispatch('metadata clear', info)

metadata_cmds = {
    'get': metadata_GET,
    'list': metadata_LIST,
    'set': metadata_SET,
    'clear': metadata_CLEAR,
}
metadata_cmds = CaseInsensitiveDict(**metadata_cmds)

@eventmgr_rfc1459.message('METADATA', min_params=2)
def m_METADATA(cli, ev_msg):
    target_name, subcmd = ev_msg['params'][:2]

    if subcmd not in metadata_cmds:
        cli.dump_numeric(400, ['METADATA', command, 'Unknown subcommand'])
        return

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

    metadata_cmds[subcmd](cli, ev_msg, target_name, target)

def set_key(target, key, value=None):
    ctx = get_context()

    # clearing key
    if value is None:
        try:
            del target.metadata[key]
            target.user_set_metadata.remove(key)
        except (KeyError, ValueError):
            pass

    # setting key
    else:
        target.metadata[key] = value

        restricted_keys = ctx.conf.metadata.get('restricted_keys', [])
        if key not in target.user_set_metadata and key not in restricted_keys:
            target.user_set_metadata.append(key)

        target.metadata[key] = value

def get_monitor_list(source, target):
    monitor_list = monitor.monitored.get(target.nickname, [])
    monitor_list += target.get_common_peers(exclude=monitor_list+[source], cap='metadata-notify')
    return monitor_list

def dump_metadata_notify(source, target, key, args, monitor_list=None, restricted_keys=None):
    if monitor_list is None:
        monitor_list = get_monitor_list(source, target)

    if restricted_keys is None:
        ctx = get_context()
        restricted_keys = ctx.conf.metadata.get('restricted_keys', [])

    for cli in monitor_list:
        if key in restricted_keys and (not cli.role or key not in cli.role.metakeys_get):
            continue
        if cli == source or cli == target:
            continue
        if cli.servername == ctx.conf.name:
            cli.dump_verb('METADATA', args)

@eventmgr_core.handler('metadata clear', priority=1, local_client='source')
def m_metadata_clear(info):
    ctx = get_context()
    restricted_keys = ctx.conf.metadata.get('restricted_keys', [])

    source = info['source']
    target = info['target']
    target_name = info['target_name']
    keys = info['keys']

    monitor_list = get_monitor_list(source, target)

    # we dump numerics to the source here instead of in the 'delete' event
    #   below so the 'end of metadata' numeric gets put in the right place
    for key, kinfo in keys.items():
        visibility = kinfo['visibility']

        args = [target_name, key, visibility]
        source.dump_numeric('761', args)

        # create event to actually remove key and dump notify
        info = {
            'key': key,
            'source': source,
            'target': target,
            'target_name': target_name,
            'visibility': visibility,
        }
        eventmgr_core.dispatch('metadata delete', info)

    source.dump_numeric('762', ['end of metadata'])

@eventmgr_core.handler('metadata delete', priority=1)
def m_metadata_delete(info):
    key = info['key']
    source = info['source']
    target = info['target']
    target_name = info['target_name']
    visibility = info['visibility']

    set_key(target, key)

    args = [target_name, key, visibility]
    dump_metadata_notify(source, target, key, args)

@eventmgr_core.handler('metadata set', priority=1)
def m_metadata_set(info):
    ctx = get_context()

    source = info['source']
    target = info['target']
    key = info['key']
    value = info['value']

    args = [info['target_name'], key, info['visibility']]
    if value:
        args.append(value)

    set_key(target, key, value)

    # if local client, dump numerics
    if source.servername == ctx.conf.name:
        source.dump_numeric('761', args)
        source.dump_numeric('762', ['end of metadata'])

    # sendto monitoring clients
    dump_metadata_notify(source, target, key, args)
