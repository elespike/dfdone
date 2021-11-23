from pathlib import Path


TEST_DIR_PATH = Path(__file__).parent
TEST_FILE_PATH = TEST_DIR_PATH.joinpath('test_constructs.tml')
TEST_OUTPUT_FILE_PATH = TEST_DIR_PATH.joinpath('test_output.html')
EXAMPLE_DIR_PATH = TEST_DIR_PATH.joinpath('../../examples').resolve()
EXAMPLE_FILE_PATH = EXAMPLE_DIR_PATH.joinpath('getting_started.tml')
OUTPUT_FILE_PATH = EXAMPLE_DIR_PATH.joinpath('output.html')
