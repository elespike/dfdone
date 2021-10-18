from datetime import datetime as dt
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


class Interaction:
    def __init__(self, timestamp, action, source, target,
                 data_threats, broad_threats, notes):
        self.created = timestamp
        self.action = action
        self.source = source
        self.target = target

        # Sort by data classification, high to low:
        data_threats = {
            k: v for k, v in sorted(
                data_threats.items(),
                key=lambda i: i[0].classification,
                reverse=True
            )
        }
        self.data_threats = data_threats
        self.broad_threats = broad_threats

        self.notes = notes

    @property
    def highest_classification(self):
        return max(d.classification for d in self.data_threats)


class Element(Component):
    def __init__(self, label, profile, role, groups, description):
        super().__init__(label, description)
        self.role = role
        self.profile = profile
        self.groups = groups
        self.interactions = list()

    @staticmethod
    def interact(action, source, destination,
                 data_threats, broad_threats, notes):
        source.interactions.append(Interaction(
            dt.utcnow().timestamp(),
            action,
            source,
            destination,
            data_threats,
            broad_threats,
            notes
        ))

    def processes(self, data_threats, broad_threats, notes):
        Element.interact(Action.PROCESS, self, self,
                         data_threats, broad_threats, notes)

    def receives(self, source_element,
                 data_threats, broad_threats, notes):
        Element.interact(Action.RECEIVE, source_element, self,
                         data_threats, broad_threats, notes)

    def sends(self, destination_element,
              data_threats, broad_threats, notes):
        Element.interact(Action.SEND, self, destination_element,
                         data_threats, broad_threats, notes)

    def stores(self, data_threats, broad_threats, notes):
        Element.interact(Action.STORE, self, self,
                         data_threats, broad_threats, notes)


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
        self.active = False
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
        self.active = False
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
