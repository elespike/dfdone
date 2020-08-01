import itertools
import unittest

from concurrent.futures import ProcessPoolExecutor, as_completed
from functools import partial

from dfdone.cli.main import build_arg_parser, main
from dfdone.tests import constants


class TestCLI(unittest.TestCase):
    OPTS_OUTPUT = {
        'assumptions' : constants.EXAMPLE_TML_OUTPUT_HTML_PARTS[0],
        'data'        : constants.EXAMPLE_TML_OUTPUT_HTML_PARTS[1],
        'threats'     : constants.EXAMPLE_TML_OUTPUT_HTML_PARTS[2],
        'measures'    : constants.EXAMPLE_TML_OUTPUT_HTML_PARTS[3],
        'diagram'     : constants.EXAMPLE_TML_OUTPUT_HTML_PARTS[4],
        'interactions': constants.EXAMPLE_TML_OUTPUT_HTML_PARTS[5],
    }
    PARSER = build_arg_parser(testing=True)
    TEST_MAIN = partial(main, return_html=True)

    @staticmethod
    def build_arg_combinations():
        arg_options = TestCLI.OPTS_OUTPUT.keys()
        arg_combinations = [
            perm for i in range(1, 4)
            for perm in itertools.permutations(arg_options, i)
        ]
        return arg_combinations

    def test_defaults(self):
        args = TestCLI.PARSER.parse_args([constants.EXAMPLE_TML_DATA])
        html = TestCLI.TEST_MAIN(args=args)
        self.assertEqual(html, constants.EXAMPLE_TML_OUTPUT)

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
                expected_output = '\n\n'.join([
                    TestCLI.OPTS_OUTPUT[o]
                    for o in effective_options
                ]).strip()

                args = [arg]
                if arg == '-i':
                    args.extend(include_options)
                if arg == '-x':
                    args.extend(exclude_options)
                args.extend(['--no-css', constants.EXAMPLE_TML_DATA])

                future = executor.submit(
                    TestCLI.TEST_MAIN,
                    args=TestCLI.PARSER.parse_args(args)
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
