from dfdone.components import (
    Datum,
    Element,
    Interaction,
    Measure,
    Threat,
)


def yield_elements(components):
    """
    See examples/getting_started.tml for Element definitions.
    >>> for c in yield_elements(components):
    ...     assert(isinstance(c, Element))
    ...     print(c.label)
    ...
    User
    Web App
    DB
    """
    for element in filter(
        lambda v: isinstance(v, Element),
        components.values()
    ):
        yield element


def yield_data(components):
    """
    See examples/getting_started.tml for Data definitions.
    >>> for c in yield_data(components):
    ...     assert(isinstance(c, Datum))
    ...     print(c.label)
    ...
    un
    pw
    session cookie
    """
    for datum in filter(
        lambda v: isinstance(v, Datum),
        components.values()
    ):
        yield datum


def yield_threats(components):
    """
    See examples/getting_started.tml and examples/sample_threats.tml
    for Threat definitions.
    >>> for c in yield_threats(components):
    ...     assert(isinstance(c, Threat))
    ...     print(c.label)
    ...
    Cross-Site Scripting
    Database Injection
    Command Injection
    Information Disclosure
    """
    for threat in filter(
        lambda v: isinstance(v, Threat) and v.active,
        components.values()
    ):
        yield threat


def yield_measures(components):
    """
    See examples/getting_started.tml for Measure definitions.
    >>> for c in yield_measures(components):
    ...     assert(isinstance(c, Measure))
    ...     print(c.label)
    ...
    Input Validation
    Parameterized Queries
    Blocking WAF
    Learning WAF
    """
    for measure in filter(
        lambda v: isinstance(v, Measure),
        components.values()
    ):
        yield measure


def yield_interactions(components):
    """
    See examples/getting_started.tml for Interaction definitions.
    >>> for c in yield_interactions(components):
    ...     assert(isinstance(c, Interaction))
    ...     print(F"{c.source} -> {c.target}")
    ...
    User -> Web App
    Web App -> DB
    Web App -> User
    """
    for e in yield_elements(components):
        for i in e.interactions:
            yield i
