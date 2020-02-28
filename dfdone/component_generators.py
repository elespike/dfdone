from dfdone.components import (
    Datum,
    Element,
    Measure,
    Threat,
)


def yield_elements(components):
    return (v for v in components.values() if isinstance(v, Element))


def yield_data(components):
    data = (v for v in components.values() if isinstance(v, Datum))
    return (
        d for d in sorted(
            data,
            key=lambda _d: _d.classification,
            reverse=True
        )
    )


def yield_threats(components):
    threats = (
        v for v in components.values()
        if isinstance(v, Threat) and v.active
    )
    return (
        t for t in sorted(
            threats,
            key=lambda _t: _t.calculate_risk(),
            reverse=True
        )
    )


def yield_measures(components):
    measures = (
        v for v in components.values()
        if isinstance(v, Measure)
    )
    return (
        m for m in sorted(
            measures,
            key=lambda _m: _m.imperative
        )
    )


def yield_interactions(components):
    return (
        i for e in yield_elements(components)
        for i in e.interactions
    )


# TODO verify this is not needed
def yield_interaction_threats(components):
    interaction_threats = set()
    for i in yield_interactions():
        for threats in i.data_threats.values():
            for t in threats:
                interaction_threats.add(t)
        for t in i.generic_threats:
            interaction_threats.add(t)
    return (t for t in sorted(interaction_threats, key=lambda t: t.label))


# TODO verify this is not needed
def yield_interaction_measures(components):
    return (
        m for t in yield_interaction_threats()
        for m in t.measures
    )
