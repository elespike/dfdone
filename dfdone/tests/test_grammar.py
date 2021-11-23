import unittest

from concurrent.futures import ProcessPoolExecutor, as_completed
from itertools import product

from dfdone.tml.grammar import constructs
from pyparsing import ParseException

# Shared syntax
QUOTED = ['"simple"', '"escaped ""quotes"""']
MULTILINE = QUOTED + ['"simple\n\tmulti\n\tline"', '"escaped\n\t""multi""\n\tline"']
VERBS = ['is', 'are']
ARTICLES = ['a', 'an', 'the']
LABELED = ['labeled ' + q for q in QUOTED]
DESCRIBED = ['described as ' + m for m in MULTILINE]
LDP = list(product(LABELED, DESCRIBED))
LABEL_AND_OR_DESCRIPTION = LABELED + DESCRIBED
LABEL_AND_OR_DESCRIPTION.extend(F"{p[0]}      {p[1]}" for p in LDP)
LABEL_AND_OR_DESCRIPTION.extend(F"{p[0]}\t    {p[1]}" for p in LDP)
LABEL_AND_OR_DESCRIPTION.extend(F"{p[0]}, and {p[1]}" for p in LDP)
LABEL_AND_OR_DESCRIPTION.extend(F"{p[0]}; and {p[1]}" for p in LDP)
LABEL_LIST = ['"A"', '"B"', '"C"', '"""D"""']

# Element syntax
PROFILES = ['white box', 'grey box', 'gray box', 'black box',
            'white-box', 'grey-box', 'gray-box', 'black-box']
ROLES = ['agent', 'service', 'storage']
CLUSTER = [''] + ['in ' + q for q in QUOTED]

# Data syntax
CLASSIFICATION  = ['public', 'confidential', 'restricted']
DATA_LITERALS  = ['datum', 'data']

# Threat syntax
HML = ['high', 'medium', 'low']
IMPACT = ['impact', 'severity']
PROBABILITY = ['probability', 'likelihood']
IMPACT_PROBABILITY = [F"{p[0]} {p[1]}, {p[2]} {p[3]}" for p in product(HML, IMPACT, HML, PROBABILITY)]
PROBABILITY_IMPACT = [F"{p[0]} {p[1]}, {p[2]} {p[3]}" for p in product(HML, PROBABILITY, HML, IMPACT)]
THREAT_LITERALS = ['threat']

# Measure syntax
CAPABILITY  = ['full', 'partial', 'detective']
MEASURE_LITERALS = [F"{p[0]} {p[1]}" for p in product(
    ['', 'security'],
    ['measure', 'mitigation', 'control'],
)]
AGAINST = ['against']

# Modification syntax
NOW = ['now']


class TestGrammar(unittest.TestCase):
    @staticmethod
    def exception_in_results(results):
        for r in results:
            exc = r[-1]
            is_exception = isinstance(exc, ParseException)
            if is_exception:
                print()
                print(exc.explain(depth=0))
            yield is_exception

    def run_tests(self, construct, tests, concurrent=False):
        if not concurrent:
            construct.run_tests(
                tests,
                print_results=False
            )
            return
        futures = list()
        with ProcessPoolExecutor() as executor:
            max_workers = executor._max_workers
            split_tests = [tests[i::max_workers] for i in range(max_workers)]
            for _tests in split_tests:
                future = executor.submit(
                    construct.run_tests,
                    _tests,
                    print_results=False,
                )
                futures.append(future)
        for future in as_completed(futures):
            results = future.result()
            self.assertFalse(
                any(TestGrammar.exception_in_results(results[1]))
            )

    def test_inclusion(self):
        inclusion_components = [
            # Literal 'include'
            ['include'],
            # Path
            ['"file.tml"', '"relative/file.tml"', '"/full/path/to/file.tml"'],
        ]
        self.run_tests(
            constructs['inclusion'],
            [' '.join(p) for p in product(*inclusion_components)],
        )

    def test_element(self):
        element_components = [
            QUOTED,
            VERBS,
            ARTICLES,
            PROFILES,
            ROLES,
            CLUSTER,
            LABEL_AND_OR_DESCRIPTION,
        ]
        self.run_tests(
            constructs['element'],
            [' '.join(p) for p in product(*element_components)],
        )

    def test_datum(self):
        datum_components = [
            QUOTED,
            VERBS,
            ARTICLES,
            CLASSIFICATION,
            DATA_LITERALS,
            LABEL_AND_OR_DESCRIPTION,
        ]
        self.run_tests(
            constructs['datum'],
            [' '.join(p) for p in product(*datum_components)],
        )

    def test_threat(self):
        threat_components = [
            QUOTED,
            VERBS,
            ARTICLES,
            IMPACT_PROBABILITY + PROBABILITY_IMPACT,
            THREAT_LITERALS,
            LABEL_AND_OR_DESCRIPTION,
        ]
        self.run_tests(
            constructs['threat'],
            [' '.join(p) for p in product(*threat_components)],
        )

    def test_measure(self):
        measure_components = [
            QUOTED,
            VERBS,
            ARTICLES,
            CAPABILITY,
            MEASURE_LITERALS,
            AGAINST,
            LABEL_LIST,
            LABEL_AND_OR_DESCRIPTION,
        ]
        self.run_tests(
            constructs['measure'],
            [' '.join(p) for p in product(*measure_components)],
            concurrent=True
        )

    def test_alias(self):
        alias_components = [
            QUOTED,
            VERBS,
            ARTICLES,
            LABEL_LIST,
        ]
        self.run_tests(
            constructs['alias'],
            [' '.join(p) for p in product(*alias_components)],
        )

    def test_modification(self):
        modification_tests = list()
        meta_modifications = [
            QUOTED,
            VERBS,
            NOW,
            LABEL_AND_OR_DESCRIPTION,
        ]
        modification_tests.extend(
            [' '.join(p) for p in product(*meta_modifications)]
        )

        element_modifications = [
            QUOTED,
            VERBS,
            NOW,
            ARTICLES,
            PROFILES,
            ROLES,
            CLUSTER,
            LABEL_AND_OR_DESCRIPTION,
        ]
        modification_tests.extend(
            [' '.join(p) for p in product(*element_modifications)]
        )

        datum_modifications = [
            QUOTED,
            VERBS,
            NOW,
            ARTICLES,
            CLASSIFICATION,
            DATA_LITERALS,
            LABEL_AND_OR_DESCRIPTION,
        ]
        modification_tests.extend(
            [' '.join(p) for p in product(*datum_modifications)]
        )

        threat_modifications = [
            QUOTED,
            VERBS,
            NOW,
            ARTICLES,
            IMPACT_PROBABILITY + PROBABILITY_IMPACT,
            THREAT_LITERALS,
            LABEL_AND_OR_DESCRIPTION,
        ]
        modification_tests.extend(
            [' '.join(p) for p in product(*threat_modifications)]
        )

        measure_modifications = [
            QUOTED,
            VERBS,
            NOW,
            ARTICLES,
            CAPABILITY,
            MEASURE_LITERALS,
            AGAINST,
            LABEL_LIST,
            LABEL_AND_OR_DESCRIPTION,
        ]
        modification_tests.extend(
            [' '.join(p) for p in product(*measure_modifications)]
        )

        self.run_tests(
            constructs['modification'],
            modification_tests,
        )

    def test_interaction(self):
        alternate_cases = {
            'default': {},
            'send': {
                'actions': ['sends', 'send'],
                'to_from': ['to', '\n\tto'],
                'target': QUOTED,
            },
            'receive': {
                'actions': ['receives', 'receive'],
                'to_from': ['from', '\n\tfrom'],
                'target': QUOTED,
            },
        }
        interaction_components = {
            'ordinals': ['1.', '(1)', '1)', '1 -'],
            'source': QUOTED,
            'actions': ['processes', 'process', 'stores', 'store'],
            'data_list': LABEL_LIST,
            'to_from': [],
            'target': [],
            'note_keywords': ['with note', ';\n\twith notes', 'note',
                              'note that', 'noting that', 'n.b.;'],
            'notes': MULTILINE,
        }
        for case, values in alternate_cases.items():
            interaction_components.update(values)
            self.run_tests(
                constructs['interaction'],
                [' '.join(p) for p in product(*interaction_components.values())],
            )

    def test_mitigation(self):
        mitigation_components = [
            QUOTED,
            ['must', 'should', 'may', 'has', 'have'],
            ['be', 'been'],
            ['implemented', 'applied', 'deployed', 'verified', 'checked'],
            ['on "username"', 'on "username", "password"',
             'on all data', 'on all data except for "username"',
             'on all data except "username", "password"',
             'on all data;\n\texcept "username", "password"'],
            ['between "User" and "Web", "Web" and "DB"',
             'between all nodes except "User" and "Web", "Web" and "DB"',
             'within "User", "Web"', 'within all nodes except "User"',
             'within all nodes except "User", "Web"',
             'between "User" and "Web", and within "DB"',
             'within "DB", and between "User" and "Web"',
             'between "User" and "Web",\n\tand within "DB"',
             'within "DB",\n\tand between "User" and "Web"'],
        ]
        self.run_tests(
            constructs['mitigation'],
            [' '.join(p) for p in product(*mitigation_components)],
            concurrent=True
        )


if __name__ == '__main__':
    unittest.main()

