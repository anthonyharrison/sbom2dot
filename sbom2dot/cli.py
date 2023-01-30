# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import argparse
import sys
import textwrap
from collections import ChainMap

from lib4sbom.output import SBOMOutput
from lib4sbom.parser import SBOMParser

from sbom2dot.dotgenerator import DOTGenerator
from sbom2dot.version import VERSION

# CLI processing


def main(argv=None):

    argv = argv or sys.argv
    app_name = "sbom2dot"
    parser = argparse.ArgumentParser(
        prog=app_name,
        description=textwrap.dedent(
            """
            SBOM2dot generates a dot file which shows the relationships
            between the components within a SBOM.
            """
        ),
    )
    input_group = parser.add_argument_group("Input")
    input_group.add_argument(
        "-i",
        "--input-file",
        action="store",
        default="",
        help="Name of SBOM file",
    )

    output_group = parser.add_argument_group("Output")
    output_group.add_argument(
        "--debug",
        action="store_true",
        default=False,
        help="add debug information",
    )

    output_group.add_argument(
        "-o",
        "--output-file",
        action="store",
        default="",
        help="output filename (default: output to stdout)",
    )

    parser.add_argument("-V", "--version", action="version", version=VERSION)

    defaults = {
        "input_file": "",
        "output_file": "",
        "debug": False,
    }

    raw_args = parser.parse_args(argv[1:])
    args = {key: value for key, value in vars(raw_args).items() if value}
    args = ChainMap(args, defaults)

    # Validate CLI parameters

    input_file = args["input_file"]

    if input_file == "":
        print("[ERROR] SBOM name must be specified.")
        return -1

    if args["debug"]:
        print("Input file", args["input_file"])
        print("Output file", args["output_file"])

    dot_parser = SBOMParser()
    # Load SBOM - will autodetect SBOM type
    try:
        dot_parser.parse_file(input_file)

        if args["debug"]:
            print(dot_parser.get_sbom()["relationships"])

        sbom_dot = DOTGenerator()
        sbom_dot.generatedot(dot_parser.get_sbom()["relationships"])
        dot_out = SBOMOutput(args["output_file"], "dot")
        dot_out.generate_output(sbom_dot.getDOT())
    except FileNotFoundError:
        print(f"{input_file} not found")

    return 0


if __name__ == "__main__":
    sys.exit(main())
