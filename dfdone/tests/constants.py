from pathlib import Path


TEST_DIR_PATH = Path(__file__).parent
TEST_TML_DATA = TEST_DIR_PATH.joinpath('test_constructs.tml').read_text()
EXAMPLE_DIR_PATH = TEST_DIR_PATH.joinpath('../../examples').resolve()
EXAMPLE_TML_DATA = EXAMPLE_DIR_PATH.joinpath('getting_started.tml').read_text()
EXAMPLE_TML_OUTPUT = EXAMPLE_DIR_PATH.joinpath('output.html').read_text()
EXAMPLE_TML_OUTPUT_CSS = F"<style>\n{EXAMPLE_DIR_PATH.joinpath('default.css').read_text()}</style>"
EXAMPLE_TML_OUTPUT_HTML = EXAMPLE_TML_OUTPUT.replace(EXAMPLE_TML_OUTPUT_CSS, '').lstrip()
EXAMPLE_TML_OUTPUT_HTML_PARTS = EXAMPLE_TML_OUTPUT_HTML.split('\n\n')
