import doctest
import unittest

from pathlib import Path

from dfdone import (
    component_generators,
)
from dfdone.tml.parser import Parser


example_path = Path(
    F"{Path(__file__).resolve().parent}/../../examples/getting_started.tml"
).resolve()
parser = Parser(example_path)


def load_tests(loader, tests, pattern):
    tests.addTests(doctest.DocTestSuite(
        component_generators,
        extraglobs={'components': parser.components}
    ))
    # tests.addTests(...)
    return tests
