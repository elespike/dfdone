import doctest

from io import StringIO

from dfdone import (
    component_generators,
)
from dfdone.tests.constants import EXAMPLE_TML_DATA
from dfdone.tml.parser import Parser


def load_tests(loader, tests, pattern):
    parser = Parser(StringIO(EXAMPLE_TML_DATA))
    tests.addTests(doctest.DocTestSuite(
        component_generators,
        extraglobs={'components': parser.components}
    ))
    # tests.addTests(...)
    return tests
