import unittest

from itertools import product

from dfdone import enums
from dfdone.components import (
    Threat,
    Measure,
)


_impact_probability_product = [
    p for p in product(enums.Impact, enums.Probability)
]
RISK_MAP = {
    enums.Risk.LOW: [
        (i, p) for i, p in _impact_probability_product
        if (i, p) in [(1, 2), (1, 1), (2, 1)]
    ],
    enums.Risk.MEDIUM: [
        (i, p) for i, p in _impact_probability_product
        if (i, p) in [(1, 3), (2, 2), (3, 1)]
    ],
    enums.Risk.HIGH: [
        (i, p) for i, p in _impact_probability_product
        if (i, p) in [(2, 3), (3, 3), (3, 2)]
    ],
}


class TestRiskCalculation(unittest.TestCase):
    def verify_risk_calculation(self, threat, measure, classification):
        impact = threat.impact
        probability = threat.probability
        if (measure.status == enums.Status.VERIFIED
        and measure.capability != enums.Capability.DETECTIVE):
            probability -= measure.capability
            probability = enums.Probability(
                max(probability, enums.Probability.LOW)
            )

        impact += classification
        impact = max(impact, enums.Impact.LOW)
        impact = min(impact, enums.Impact.HIGH)
        impact = enums.Impact(impact)
        calculated_risk = threat.calculate_risk(classification)
        self.assertTrue(
            (impact, probability) in RISK_MAP[calculated_risk]
        )

    def test_risk_combinations(self):
        threat = Threat('', 0, 0, '')
        measure = Measure('', 0, '')
        for (impact, probability), capability in product(
            product(enums.Impact, enums.Probability),
            enums.Capability
        ):
            threat.impact = impact
            threat.probability = probability
            measure.capability = capability
            for status in enums.Status:
                measure.status = status
                threat._measures = {measure}
                for classification in enums.Classification:
                    self.verify_risk_calculation(
                        threat,
                        measure,
                        classification
                    )
