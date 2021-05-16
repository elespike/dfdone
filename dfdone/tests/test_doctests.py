import doctest

from io import StringIO

from dfdone import (
    component_generators,
)
from dfdone.tests.constants import EXAMPLE_TML_DATA, TEST_TML_DATA
from dfdone.tml import parser


def load_tests(loader, tests, pattern):
    example_parser = parser.Parser(StringIO(EXAMPLE_TML_DATA))
    tests.addTests(doctest.DocTestSuite(
        component_generators,
        extraglobs={'components': example_parser.components}
    ))
    test_model_file = StringIO(TEST_TML_DATA)
    test_parser = parser.Parser(test_model_file, log_level=40)  # logging.ERROR
    tests.addTests(doctest.DocTestSuite(
        parser,
        extraglobs={
            'parser': test_parser,
        }
    ))
    # tests.addTests(doctest.DocTestSuite(
    # ))
    return tests
