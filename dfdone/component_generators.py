from dfdone.components import (
    Datum,
    Element,
    Measure,
    Threat,
)


def yield_elements(components):
    return (v for v in components.values() if isinstance(v, Element))


def yield_data(components):
    data = [v for v in components.values() if isinstance(v, Datum)]
    data.sort(key=lambda d: d.label)
    data.sort(key=lambda d: d.classification, reverse=True)
    return (data)


def yield_threats(components):
    threats = [
        v for v in components.values()
        if isinstance(v, Threat) and v.active
    ]
    threats.sort(key=lambda t: t.label)
    threats.sort(key=lambda t: t.calculate_risk(), reverse=True)
    return (threats)


def yield_measures(components):
    measures = [
        v for v in components.values()
        if isinstance(v, Measure)
    ]
    measures.sort(key=lambda m: m.label)
    measures.sort(key=lambda m: m.capability, reverse=True)
    return (measures)


def yield_interactions(components):
    return (
        i for e in yield_elements(components)
        for i in e.interactions
    )
