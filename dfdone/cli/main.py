import click
import re

from collections import defaultdict as ddict
from graphviz import Digraph

from dfdone.components import Datum, Element, Interaction
from dfdone.enums import Profile, Role, Risk
from dfdone.threats import assumptions
from dfdone.plot import plot


# TODO figure out how to determine whether threats have been
# mitigated or accepted by looking at markers in actual product code.

# TODO include a link to mitigations/acceptances in the TM artifact.

message = """
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
##      ##    ###    ########  ##    ## #### ##    ##  ######
##  ##  ##   ## ##   ##     ## ###   ##  ##  ###   ## ##    ##
##  ##  ##  ##   ##  ##     ## ####  ##  ##  ####  ## ##
##  ##  ## ##     ## ########  ## ## ##  ##  ## ## ## ##   ####
##  ##  ## ######### ##   ##   ##  ####  ##  ##  #### ##    ##
##  ##  ## ##     ## ##    ##  ##   ###  ##  ##   ### ##    ##
 ###  ###  ##     ## ##     ## ##    ## #### ##    ##  ######
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

We are about to exec({})! If you don't know what this means, stop now.
Otherwise, make sure you trust the contents of that file before proceeding.
Proceed?"""

@click.command()
@click.argument('model')
def main(model):
    with open(model) as f:
        model_data = f.read()
    _globals = dict()
    _locals = dict()
    if click.confirm(message.format(model), abort=True):
        exec(model_data, _globals, _locals)
    plot(_locals, assumptions)

