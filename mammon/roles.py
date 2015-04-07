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

from mammon.utility import CaseInsensitiveList

default_whois_format = 'is a {role}.'
default_vowel_whois_format = 'is an {role}.'

class Role:
    def __init__(self, ctx, name, roles=None, extends=None, **kwargs):
        self.ctx = ctx
        self.name = name

        # defaults
        self.metakeys_get = []
        self.metakeys_set = []
        self.metakeys_access = []
        self.capabilities = []
        self.title = ''
        self.whois_format = None

        for k, v in kwargs.items():
            if v:
                setattr(self, k, v)

        # metadata
        for key in self.metakeys_access:
            if key not in self.metakeys_get:
                self.metakeys_get.append(key)
            if key not in self.metakeys_set:
                self.metakeys_set.append(key)
        del self.metakeys_access

        self.metakeys_get = CaseInsensitiveList(self.metakeys_get)
        self.metakeys_set = CaseInsensitiveList(self.metakeys_set)

        # automatically choose a/an for whois message
        if self.whois_format is None:
            self.whois_format = default_whois_format
            for character in self.title:
                if character.isalpha() and character.lower() in ['a', 'e', 'i', 'o', 'u']:
                    self.whois_format = default_vowel_whois_format
                    break
                elif character.isalpha():
                    break

        self.whois_line = self.whois_format.format(role=self.title)

        # extending roles
        if roles is None:
            roles = self.ctx.roles

        if extends and extends in roles:
            role = roles.get(extends)
            for capability in role.capabilities:
                if capability not in self.capabilities:
                    self.capabilities.append(capability)
            for key in role.metakeys_get:
                if key not in self.metakeys_get:
                    self.metakeys_get.append(key)
            for key in role.metakeys_set:
                if key not in self.metakeys_set:
                    self.metakeys_set.append(key)
        elif extends:
            print('mammon: error: error in role', name, '- extending role', extends, 'does not exist')
