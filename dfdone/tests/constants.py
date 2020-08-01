from pathlib import Path


EXAMPLE_DIR_PATH = Path(
    F"{Path(__file__).resolve().parent}/../../examples"
).resolve()

with EXAMPLE_DIR_PATH.joinpath('getting_started.tml').open() as f:
    EXAMPLE_TML_DATA = f.read()

with EXAMPLE_DIR_PATH.joinpath('output.html').open() as f:
    EXAMPLE_TML_OUTPUT = f.read()

EXAMPLE_TML_OUTPUT_CSS = EXAMPLE_TML_OUTPUT.split('</style>\n\n')[0] + '</style>'
EXAMPLE_TML_OUTPUT_HTML = EXAMPLE_TML_OUTPUT.replace(EXAMPLE_TML_OUTPUT_CSS, '').lstrip()
EXAMPLE_TML_OUTPUT_HTML_PARTS = EXAMPLE_TML_OUTPUT_HTML.split('\n\n')
