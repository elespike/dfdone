import itertools
import unittest

from concurrent.futures import ProcessPoolExecutor, as_completed
from functools import partial

from dfdone.cli.main import build_arg_parser, main, SECTION_BREAK
from dfdone.tests import constants


SECTIONS = constants.TEST_OUTPUT_FILE_PATH.read_text().split(SECTION_BREAK)
class TestCLI(unittest.TestCase):
    OPTS_OUTPUT = {
        k: SECTIONS[i]
        for i, k in enumerate([
            'data',
            'diagram',
            'interactions',
            'threats',
            'measures',
        ])
    }
    PARSER = build_arg_parser(testing=True)
    TEST_MAIN = partial(main, return_html=True)

    maxDiff = None

    @staticmethod
    def build_arg_combinations():
        arg_options = TestCLI.OPTS_OUTPUT.keys()
        arg_combinations = [
            perm for i in range(1, 4)
            for perm in itertools.permutations(arg_options, i)
        ]
        for o in arg_options:
            arg_combinations.append((o, o))
        return arg_combinations

    def test_defaults(self):
        args = TestCLI.PARSER.parse_args([constants.EXAMPLE_FILE_PATH.read_text()])
        html = TestCLI.TEST_MAIN(args=args)
        self.assertEqual(html, constants.OUTPUT_FILE_PATH.read_text())

    def run_incl_excl_tests(self, include_combinations,
                            exclude_combinations, arg):
        self.assertEqual(len(include_combinations), len(exclude_combinations))
        print('(', end='')
        with ProcessPoolExecutor() as executor:
            futures_outputs = dict()
            for include_options, exclude_options in zip(
                include_combinations, exclude_combinations
            ):
                effective_options = [
                    o for o in include_options
                    if o not in exclude_options
                ]
                expected_output = SECTION_BREAK.join([
                    TestCLI.OPTS_OUTPUT[o]
                    for o in effective_options
                ]).strip()

                args = [arg]
                if arg == '-i':
                    args.extend(include_options)
                if arg == '-x':
                    args.extend(exclude_options)
                args.extend(['--no-css', '--no-anchors', constants.EXAMPLE_FILE_PATH.read_text()])

                future = executor.submit(
                    TestCLI.TEST_MAIN,
                    args=TestCLI.PARSER.parse_args(args),
                )
                futures_outputs[future] = expected_output

            for future in as_completed(futures_outputs):
                result = future.result()
                self.assertEqual(result, futures_outputs[future])
                print('.', end='', flush=True)
        print(')', end='', flush=True)

    def test_inclusion(self):
        include_combinations = TestCLI.build_arg_combinations()
        self.run_incl_excl_tests(
            include_combinations,
            [tuple() for c in include_combinations],
            '-i'
        )

    def test_exclusion(self):
        exclude_combinations = TestCLI.build_arg_combinations()
        self.run_incl_excl_tests(
            [TestCLI.OPTS_OUTPUT.keys() for c in exclude_combinations],
            exclude_combinations,
            '-x'
        )
