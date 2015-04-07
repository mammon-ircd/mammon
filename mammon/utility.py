# mammon - utility/third-party stuff, each thing has it's own header and provenance
# information.

# CaseInsensitiveDict from requests.
#
# Copyright 2015 Kenneth Reitz
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

import time
import collections

class CaseInsensitiveDict(collections.MutableMapping):
    """
    A case-insensitive ``dict``-like object.
    Implements all methods and operations of
    ``collections.MutableMapping`` as well as dict's ``copy``. Also
    provides ``lower_items``.
    All keys are expected to be strings. The structure remembers the
    case of the last key to be set, and ``iter(instance)``,
    ``keys()``, ``items()``, ``iterkeys()``, and ``iteritems()``
    will contain case-sensitive keys. However, querying and contains
    testing is case insensitive::
        cid = CaseInsensitiveDict()
        cid['Accept'] = 'application/json'
        cid['aCCEPT'] == 'application/json'  # True
        list(cid) == ['Accept']  # True
    For example, ``headers['content-encoding']`` will return the
    value of a ``'Content-Encoding'`` response header, regardless
    of how the header name was originally stored.
    If the constructor, ``.update``, or equality comparison
    operations are given keys that have equal ``.casefold()``s, the
    behavior is undefined.
    """
    def __init__(self, data=None, **kwargs):
        self._store = dict()
        if data is None:
            data = {}
        self.update(data, **kwargs)

    def __setitem__(self, key, value):
        # Use the lowercased key for lookups, but store the actual
        # key alongside the value.
        self._store[key.casefold()] = (key, value)

    def __getitem__(self, key):
        return self._store[key.casefold()][1]

    def __delitem__(self, key):
        del self._store[key.casefold()]

    def __iter__(self):
        return (casedkey for casedkey, mappedvalue in self._store.values())

    def __len__(self):
        return len(self._store)

    def lower_items(self):
        """Like iteritems(), but with all lowercase keys."""
        return (
            (lowerkey, keyval[1])
            for (lowerkey, keyval)
            in self._store.items()
        )

    def __eq__(self, other):
        if isinstance(other, collections.Mapping):
            other = CaseInsensitiveDict(other)
        else:
            return NotImplemented
        # Compare insensitively
        return dict(self.lower_items()) == dict(other.lower_items())

    # Copy is required
    def copy(self):
        return CaseInsensitiveDict(self._store.values())

    def __repr__(self):
        return str(dict(self.items()))

# a modified ExpiringDict implementation
#
# Copyright 2013-2015 Rackspace
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

class ExpiringDict(collections.OrderedDict):
    def __init__(self, max_len, max_age_seconds):
        collections.OrderedDict.__init__(self)
        self.max_len = max_len
        self.max_age = max_age_seconds

    def __contains__(self, key):
        try:
            item = collections.OrderedDict.__getitem__(self, key.casefold())
            if time.time() - item[1] < self.max_age:
                return True
            else:
                del self[key.casefold()]
        except KeyError:
            pass
        return False

    def __getitem__(self, key, with_age=False, max_age=None):
        item = collections.OrderedDict.__getitem__(self, key.casefold())
        item_age = time.time() - item[1]
        if not max_age:
            max_age = self.max_age
        if item_age < max_age:
            if with_age:
                return item[0], item_age
            else:
                return item[0]
        else:
            del self[key.casefold()]
            raise KeyError(key.casefold())

    def __setitem__(self, key, value):
        if len(self) == self.max_len:
            self.popitem(last=False)
        collections.OrderedDict.__setitem__(self, key.casefold(), (value, time.time()))

    def pop(self, key, default=None):
        try:
            item = collections.OrderedDict.__getitem__(self, key.casefold())
            del self[key.casefold()]
            return item[0]
        except KeyError:
            return default

    def get(self, key, default=None, with_age=False, max_age=None):
        try:
            return self.__getitem__(key.casefold(), with_age, max_age)
        except KeyError:
            if with_age:
                return default, None
            else:
                return default

    def put(self, key, value, ts=None):
        if len(self) == self.max_len:
            self.popitem(last=False)
        if not ts:
            ts = time.time()
        collections.OrderedDict.__setitem__(self, key.casefold(), (value, ts))

    def items(self):
        r = []
        for key in self:
            try:
                r.append((key, self[key]))
            except KeyError:
                pass
        return r

    def values(self):
        r = []
        for key in self:
            try:
                r.append(self[key])
            except KeyError:
                pass
        return r

    def fromkeys(self):
        raise NotImplementedError()
    def iteritems(self):
        raise NotImplementedError()
    def itervalues(self):
        raise NotImplementedError()
    def viewitems(self):
        raise NotImplementedError()
    def viewkeys(self):
        raise NotImplementedError()
    def viewvalues(self):
        raise NotImplementedError()

# just a custom casefolding list, designed for things like lists of keys
class CaseInsensitiveList(collections.MutableSequence):
    @staticmethod
    def _check_value(value):
        if not isinstance(value, object):
           raise TypeError()

    def __init__(self, data=None):
        self.__store = []

        if data:
            self.extend(data)

    def __getitem__(self, key):
        # try:except is here so iterating works properly
        try:
            return self.__store[key]
        except KeyError:
            raise IndexError

    def __setitem__(self, key, value):
        if isinstance(value, str):
            value = value.casefold()

        self.__checkValue(value)
        self.__store[key] = value

    def __delitem__(self, key):
        del self.__store[key]

    def __len__(self):
        return len(self.__store)

    def insert(self, key, value):
        if isinstance(value, str):
            value = value.casefold()

        self._check_value(value)
        self.__store.insert(key, value)

    def __contains__(self, value):
        if isinstance(value, str):
            value = value.casefold()

        return value in self.__store

# fast irc casemapping validation
# part of mammon, under mammon license.
import string

special = '_-|^{}[]`'

nick_allowed_chars = string.ascii_letters + string.digits + special
nick_allowed_chars_tbl = str.maketrans('', '', nick_allowed_chars)

first_nick_allowed_chars = string.ascii_letters + special

def validate_nick(nick):
    if nick[0] not in first_nick_allowed_chars:
        return False
    remainder = nick[1:]
    badchars = remainder.translate(nick_allowed_chars_tbl)
    return badchars == ''

chan_allowed_chars = string.ascii_letters + string.digits + special + '`~!@#$%^&*()+=|\\<>/?'
chan_allowed_chars_tbl = str.maketrans('', '', chan_allowed_chars)

def validate_chan(chan_name):
    if chan_name[0] != '#':
        return False
    badchars = chan_name[1:].translate(chan_allowed_chars_tbl)
    return badchars == ''

def uniq(input):
    output = []
    for x in input:
        if x not in output:
            output.append(x)
    return output

class UserHost:
    def __init__(self, nuh):
        self.nuh = nuh

    # XXX - put try:except on these just in case doesn't exist
    @property
    def nickname(self):
        return self.nuh.split('!')[0]

    @property
    def username(self):
        return self.nuh.split('!')[1].split('@')[0]

    @property
    def hostname(self):
        return self.nug.split('@')[1]
