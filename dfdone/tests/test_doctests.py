import doctest

from io import StringIO
from logging import ERROR

from dfdone import (
    component_generators,
)
from dfdone.tests.constants import EXAMPLE_FILE_PATH, TEST_FILE_PATH
from dfdone.tml import parser


def load_tests(loader, tests, pattern):
    example_file = StringIO(EXAMPLE_FILE_PATH.read_text())
    example_parser = parser.Parser(example_file)
    example_parser.logger.setLevel(ERROR)
    tests.addTests(doctest.DocTestSuite(
        component_generators,
        extraglobs={'components': example_parser.components}
    ))
    test_file = StringIO(TEST_FILE_PATH.read_text())
    test_parser = parser.Parser(test_file)
    test_parser.logger.setLevel(ERROR)
    tests.addTests(doctest.DocTestSuite(
        parser,
        extraglobs={
            'parser': test_parser,
        }
    ))

    # tests.addTests(doctest.DocTestSuite(
    # ))
    return tests
