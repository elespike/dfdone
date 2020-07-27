from dfdone.components import (
    Datum,
    Element,
    Measure,
    Threat,
)


def yield_elements(components):
    for element in filter(
        lambda v: isinstance(v, Element),
        components.values()
    ):
        yield element


def yield_data(components):
    for datum in filter(
        lambda v: isinstance(v, Datum),
        components.values()
    ):
        yield datum


def yield_threats(components):
    for threat in filter(
        lambda v: isinstance(v, Threat) and v.active,
        components.values()
    ):
        yield threat


def yield_measures(components):
    for measure in filter(
        lambda v: isinstance(v, Measure),
        components.values()
    ):
        yield measure


def yield_interactions(components):
    for e in yield_elements(components):
        for i in e.interactions:
            yield i
