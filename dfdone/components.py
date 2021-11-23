from itertools import chain
from operator import attrgetter, methodcaller

from dfdone.enums import (
    Action,
    Classification,
    Impact,
    Imperative,
    Probability,
    Risk,
    Status,
)


class Component:
    def __init__(self, label, description):
        self.active = False
        self._id = label  # the original label will serve as a read-only ID
        self.label = label  # this label property can be modified
        self.description = description

    @property
    def id(self):
        return self._id

    def __repr__(self):
        return self.id

    def __str__(self):
        if self.description:
            return F"{self.label}: {self.description}"
        return self.label


class Datum(Component):
    def __init__(self, label, classification, description):
        super().__init__(label, description)
        self.classification = classification


class Element(Component):
    def __init__(self, label, profile, role, clusters, description):
        super().__init__(label, description)
        self.role = role
        self.profile = profile
        self.clusters = clusters
        self.interactions = set()

class Interaction(Component):
    ORDINAL = 0
    def __init__(self, action, source, target, data, description):
        if action not in Action:
            raise ValueError('action must be one of dfdone.enums.Action')

        Interaction.ORDINAL += 1
        super().__init__(Interaction.ORDINAL, description)

        self.active = True
        self.action = action
        self.label = str(self.id)

        self.source = source
        self.target = target

        data = sorted(data, key=attrgetter('classification'), reverse=True)
        self.data_threats = {d: set() for d in data}
        self.interaction_threats = set()

        self.source.active, self.target.active = True, True
        self.source.interactions.add(self)
        self.target.interactions.add(self)

    @property
    def highest_risk(self):
        return max((t.calculate_risk(self.highest_classification) for t in chain(
            *self.data_threats.values(), self.interaction_threats
        )), default=0)

    @property
    def highest_classification(self):
        return max(d.classification for d in self.data_threats)


class Threat(Component):
    RISK_MATRIX = {
        1: Risk.LOW,
        2: Risk.LOW,
        3: Risk.LOW,
        4: Risk.MEDIUM,
        5: Risk.HIGH,
        6: Risk.HIGH,
        7: Risk.HIGH,
    }

    def __init__(self, label, impact, probability, description):
        super().__init__(label, description)
        self.impact, self.probability = impact, probability
        self._measures = set()

    @property
    def measures(self):
        for measure in sorted(
            sorted(self._measures, key=attrgetter('label')),
            key=attrgetter('capability', 'imperative', 'status'),
            reverse=True
        ):
            yield measure

    # Defauting to Classification.RESTRICTED effectively means that
    # only impact and probability will be significant in the calculation.
    def calculate_risk(self, classification=Classification.RESTRICTED):
        """
        Calculates and assigns a low/medium/high risk value
        based on the threat's impact and probability of exploitation,
        taking into account the sensitivity of the affected data
        as well as all security measures that have been verified.
        """
        _probability = self.probability
        for m in self.measures:
            if m.status != Status.VERIFIED:
                continue
            _probability -= m.capability
        _probability = max(_probability, Probability.LOW)

        _impact = self.impact
        _impact += classification
        _impact = max(_impact, Impact.LOW)
        _impact = min(_impact, Impact.HIGH)
        return Threat.RISK_MATRIX[_impact + _probability]


class Measure(Component):
    def __init__(self, label, capability, description):
        super().__init__(label, description)
        self.capability = capability
        self._threats = set()
        self.imperative = Imperative.MUST
        self.status = Status.PENDING

    @property
    def threats(self):
        for threat in sorted(
            sorted(self._threats, key=attrgetter('label')),
            key=methodcaller('calculate_risk'),
            reverse=True
        ):
            yield threat
