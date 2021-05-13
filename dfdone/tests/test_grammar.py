import unittest

from itertools import product

from dfdone.tml.grammar import constructs
from pyparsing import ParseException


class TestGrammar(unittest.TestCase):
    @staticmethod
    def exception_in_results(results):
        for r in results:
            exc = r[-1]
            is_exception = isinstance(exc, ParseException)
            if is_exception:
                print()
                print(exc.explain(exc, depth=0))
            yield is_exception

    def run_tests(self, construct, tests):
        # TODO consider splitting into processes
        results = construct.runTests(
            tests,
            printResults=False
        )
        self.assertFalse(
            any(TestGrammar.exception_in_results(results[1]))
        )

    def test_inclusion(self):
        inclusion_components = [
            # Literal 'include'
            ['include'],
            # Path
            ['"/path/to/file.tml"', '"/path/to/dir"'],
            # Label and exceptions
            ['as "assumptions"',
             'as "assumptions", except for "assume the worst"'],
        ]
        self.run_tests(
            constructs['inclusion'],
            [' '.join(p) for p in product(*inclusion_components)]
        )

    def test_element(self):
        element_components = [
            # Label
            ['"the ""awesomator"""'],
            # Verbs
            ['is', 'are'],
            # Articles
            ['a', 'an', 'the'],
            # Profiles
            ['white box', 'grey box', 'gray box', 'black box',
             'white-box', 'grey-box', 'gray-box', 'black-box'],
            # Roles
            ['agent', 'service', 'storage'],
            # Group
            ['in "the ""awesome"" group"'],
            # Description
            ['described as "automatically makes things awesome"',
             'described as "this\n\tis\n\tmulti\n\tline"']
        ]
        self.run_tests(
            constructs['element'],
            [' '.join(p) for p in product(*element_components)]
        )

    def test_datum(self):
        datum_components = [
            # Label
            ['"the ""username"""'],
            # Verbs
            ['is', 'are'],
            # Articles
            ['a', 'an', 'the'],
            # Classification
            ['public', 'confidential', 'restricted'],
            # Literals 'datum' or 'data'
            ['datum', 'data'],
            # Description
            ['described as "one\'s ""true"" identity"']
        ]
        self.run_tests(
            constructs['datum'],
            [' '.join(p) for p in product(*datum_components)]
        )

    def test_threat(self):
        threat_components = [
            # Label
            ['"Cross-site ""sKr1p71n9"""'],
            # Verbs
            ['is', 'are'],
            # Articles
            ['a', 'an', 'the'],
            # Impact
            ['high', 'medium', 'low'],
            ['impact', 'severity'],
            # Probability
            ['high', 'medium', 'low'],
            ['probability', 'likelihood'],
            # Literal 'threat'
            ['threat'],
            # Description
            ['described as "you ""probably"" suffer from it"']
        ]
        self.run_tests(
            constructs['threat'],
            [' '.join(p) for p in product(*threat_components)]
        )

    def test_measure(self):
        measure_components = [
            # Label
            ['"Input ""validation"""'],
            # Verbs
            ['is', 'are'],
            # Articles
            ['a', 'an', 'the'],
            # Capability
            ['full', 'partial', 'detective'],
            # Literals
            ['', 'security'],
            ['measure', 'mitigation', 'control'],
            ['against'],
            # Threat list
            ['"XSS", "SQLi"'],
            # Description
            ['described as "you ""probably"" should implement some"']
        ]
        self.run_tests(
            constructs['measure'],
            [' '.join(p) for p in product(*measure_components)]
        )

    def test_list(self):
        list_components = [
            # Label
            ['"""Standard"" threats"'],
            # Verbs
            ['is', 'are'],
            # Articles
            ['a', 'an', 'the'],
            # List
            ['"XSS", "CSRF", "SSRF", "APT (""KGB"")"']
        ]
        self.run_tests(
            constructs['list'],
            [' '.join(p) for p in product(*list_components)]
        )

    def test_modification(self):
        modification_tests = list()
        meta_modifications = [
            # Label
            ['"This ""thing"""'],
            # Verbs
            ['is', 'are'],
            # Literal 'now'
            ['now'],
            # New name or description
            ['labeled', 'described as'],
            ['"exactly what it ""seems"""']
        ]
        modification_tests.extend(
            [' '.join(p) for p in product(*meta_modifications)]
        )

        element_modifications = [
            # Label
            ['"This ""thing"""'],
            # Verbs
            ['is', 'are'],
            # Literal 'now'
            ['now'],
            # Articles
            ['a', 'an', 'the'],
            # Profiles and roles
            ['white box', 'agent', 'white box agent'],
            # Group
            ['', 'in "the ""awesome"" group"'],
            # Description
            ['', 'described as "exactly what it ""seems"""']
        ]
        modification_tests.extend(
            [' '.join(p) for p in product(*element_modifications)]
        )

        datum_modifications = [
            # Label
            ['"This ""thing"""'],
            # Verbs
            ['is', 'are'],
            # Literal 'now'
            ['now'],
            # Articles
            ['a', 'an', 'the'],
            # Classification
            ['public'],
            # Literals 'datum' or 'data'
            ['datum', 'data'],
            # Description
            ['', 'described as "exactly what it ""seems"""']
        ]
        modification_tests.extend(
            [' '.join(p) for p in product(*datum_modifications)]
        )

        threat_modifications = [
            # Label
            ['"This ""thing"""'],
            # Verbs
            ['is', 'are'],
            # Literal 'now'
            ['now'],
            # Articles
            ['a', 'an', 'the'],
            # Impact and probability
            ['high impact', 'high probability',
             'high impact, high probability'],
            # Literal 'threat'
            ['threat'],
            # Description
            ['', 'described as "exactly what it ""seems"""']
        ]
        modification_tests.extend(
            [' '.join(p) for p in product(*threat_modifications)]
        )

        measure_modifications = [
            # Label
            ['"This ""thing"""'],
            # Verbs
            ['is', 'are'],
            # Literal 'now'
            ['now'],
            # Articles
            ['a', 'an', 'the'],
            # Capability and threat list with literal 'measure'
            ['full measure', 'measure against "XSS", "SQLi"',
             'full measure against "XSS", "SQLi"'],
            # Description
            ['', 'described as "exactly what it ""seems"""']
        ]
        modification_tests.extend(
            [' '.join(p) for p in product(*measure_modifications)]
        )

        self.run_tests(
            constructs['modification'],
            modification_tests
        )

    def test_assumption(self):
        assumption_tests = [
            'disprove "No transport security!"',
            'disprove "bad1", "bad2", "bad3"',
        ]
        self.run_tests(
            constructs['assumption'],
            assumption_tests
        )

    def test_interaction(self):
        interaction_components = [
            # Ordinals
            ['1.', '(1)', '1)', '1 -'],
            # Subject
            ['"Element ""One"""'],
            # Actions
            ['sends', 'receives', 'stores'],
            # Effect list
            [(
                '"Datum ""One""", risking "XSS", "CSRF"; '
                '"Data ""Two"""\n\trisking "SSRF"; '
                '"Data 3"'
            )],
            # Literals 'to' or 'from'
            ['to', 'from', '\n\tto'],
            # Object
            ['"Element ""Two"""'],
            # Threat list
            ['broadly', 'generally', ',\n\tbroadly'],
            ['risking """KGB""", "other APTs"'],
            # Notes
            ['with note', ';\n\twith notes', 'note',
             'note that', 'noting that'],
            ['"this is of great concern"', '"this\n\tis\n\tmulti\n\tline"']
        ]
        self.run_tests(
            constructs['interaction'],
            [' '.join(p) for p in product(*interaction_components)]
        )

    def test_mitigation(self):
        mitigation_components = [
            # Label
            ['"Input ""validation"""'],
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
            [' '.join(p) for p in product(*mitigation_components)]
        )


if __name__ == '__main__':
    unittest.main()
