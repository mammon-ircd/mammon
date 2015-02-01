# mammon

`mammon` and `mammond` are built ontop of `ircreactor`, an ircv3.2 compliant message
bus implementation.  `ircreactor` provides the bus implementation, while `mammond` provides
the interpretation.  `mammon` is just a control tool for `mammond`.

mammon operates on the principle of a message transform pipeline.  Messages are translated
into intermediate representation by `ircreactor`, turned into lower-level representation by
`mammond` and then the effects of the low-level IR are applied to the global network state.

This allows for numerous advantages, such as the ability to prove the functional correctness
of the interpretation, verses the IRCv3 specifications and RFC1459, as well as complete
visualization of the side-effects of IRC messages (thus hopefully driving a more correct
client protocol in the future).

## todo

There are many things where help would be welcome.  Some of the goals are below.

 * implement lots of missing things (IRCv3.1/3.2-draft compliance)
 * actually implement server linking
 * implement services-less IAL/SASL (this depends on the IRCv3.2/3.3 proposal I submitted)

## install / running

Once ready for use, we will provide a setup.py which will install it.  Then you will just do something like

`mammond --config /path/to/mammond.conf`

## dependencies

Normally one might deploy mammon using `pip install mammon`, which will install all the dependencies
(of course, this only applies once we ship something).

In the meantime the dependencies are:

 * Python 3.4 (or Python 3.3+ with Tulip, or PyPy SVN with Tulip),
 * `ircmatch` library,
 * `ircreactor` library,
 * `PyYAML` library.

## contact

Join us at `irc.dereferenced.org #mammon` or `irc.dereferenced.org #offtopic` (for now).
