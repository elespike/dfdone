from dfdone.components import (
    Datum,
    Element,
    Interaction,  # for the yield_interactions tests.
    Measure,
    Threat,
)


def _yield_components(components, of_type):
    for component in filter(
        lambda v: isinstance(v, of_type) and v.active,
        components.values()
    ):
        yield component


def yield_elements(components):
    """
    Yields each dfdone.components.Element found in the supplied iterator.
    See examples/getting_started.tml for Element definitions.
    >>> for c in yield_elements(components):
    ...     assert isinstance(c, Element)
    ...     print(c.label)
    ...
    User
    Web App
    DB
    """
    for element in _yield_components(components, Element):
        yield element


def yield_data(components):
    """
    Yields each dfdone.components.Datum found in the supplied iterator.
    See examples/getting_started.tml for Data definitions.
    >>> for c in yield_data(components):
    ...     assert isinstance(c, Datum)
    ...     print(c.label)
    ...
    un
    pw
    session cookie
    """
    for datum in _yield_components(components, Datum):
        yield datum


def yield_threats(components):
    """
    Yields each dfdone.components.Threat found in the supplied iterator.
    See examples/getting_started.tml and examples/sample_threats.tml
    for Threat definitions.
    >>> for c in yield_threats(components):
    ...     assert isinstance(c, Threat)
    ...     print(c.label)
    ...
    Cross-Site Scripting
    Database Injection
    Command Injection
    Information Disclosure
    """
    for threat in _yield_components(components, Threat):
        yield threat


def yield_measures(components):
    """
    Yields each dfdone.components.Measure found in the supplied iterator.
    See examples/getting_started.tml for Measure definitions.
    >>> for c in yield_measures(components):
    ...     assert isinstance(c, Measure)
    ...     print(c.label)
    ...
    Input Validation
    Parameterized Queries
    Blocking WAF
    Learning WAF
    Error Handling
    """
    for measure in _yield_components(components, Measure):
        yield measure


def yield_interactions(components):
    """
    Yields each dfdone.components.Interaction found in the supplied iterator.
    See examples/getting_started.tml for Interaction definitions.
    >>> for c in yield_interactions(components):
    ...     assert isinstance(c, Interaction)
    ...     print(F"{c.source} -> {c.target}")
    ...
    User -> Web App
    Web App -> DB
    Web App -> User
    """
    for interaction in _yield_components(components, Interaction):
        yield interaction

