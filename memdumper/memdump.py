#!/usr/bin/env python3

# pylint: disable = line-too-long, too-many-lines, no-name-in-module, missing-docstring, too-many-return-statements, anomalous-backslash-in-string, too-many-branches, no-self-use, unused-wildcard-import, wildcard-import, fixme, too-many-statements, invalid-name, broad-except
import shutil
import textwrap
import os
import sys
import argparse
import logging
import json
import pprint

import frida
import frida.core
import utils


def main():
    parser = argparse.ArgumentParser(
        prog="memdumper",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent(""),
    )

    parser.add_argument(
        "-p", "--process", help="the process that you will be injecting to"
    )
    parser.add_argument(
        "-o",
        "--outdir",
        type=str,
        metavar="dir",
        help="provide full output directory path. (def: 'dump')",
    )
    parser.add_argument(
        "-U", "--usb", action="store_true", help="device connected over usb"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose")
    parser.add_argument(
        "-r",
        "--read-only",
        action="store_true",
        help="dump read-only parts of memory. More data, more errors",
    )
    arguments = parser.parse_args()

    # Define Configurations
    process = arguments.process
    max_chunk_size = 1e7  # 10MB

    outdir = os.path.join(os.getcwd(), "dump")
    if arguments.outdir:
        outdir = arguments.outdir

    PERMS = "rwx"
    if arguments.read_only:
        PERMS = "r--"

    if arguments.verbose:
        logging.basicConfig(format="%(levelname)s:%(message)s", level=logging.DEBUG)
    else:
        logging.basicConfig(format="%(levelname)s:%(message)s", level=logging.INFO)

    session = None
    try:
        if arguments.usb:
            session = frida.get_usb_device().attach(process)
        else:
            session = frida.attach(process)
    except Exception as e:
        logging.error("Can't connect to App")
        logging.error(str(e))
        sys.exit()

    # Selecting Output directory
    shutil.rmtree(outdir, ignore_errors=True)
    os.makedirs(outdir)

    logging.info("Starting Memory dump...")

    script = session.create_script(
        """'use strict';

        rpc.exports = {
          enumerateRanges: function (prot) {
            return Process.enumerateRangesSync(prot);
          },
          readMemory: function (address, size) {
            return Memory.readByteArray(ptr(address), size);
          }
        };

        """
    )
    script.on("message", utils.frida_on_message)
    script.load()

    agent = script.exports_sync
    mem_ranges = agent.enumerate_ranges(PERMS)

    # TODO: Make an extension to dump all region names
    # import json
    logging.debug("All sections:")
    logging.debug("===============")
    pprint.pprint(mem_ranges)

    # Performing the memory dump
    for idx, mem_range in enumerate(mem_ranges):
        base = mem_range["base"]
        size = mem_range["size"]
        # if (not "file" in mem_range
        #         or not "path" in mem_range["file"]):
        #     continue

        # if not "dalvik-main" in mem_range["file"]["path"]:
        #     continue

        filename = ""
        if "file" in mem_range and "path" in mem_range["file"]:
            filename = mem_range["file"]["path"].split("/")[-1]
        else:
            filename = "unknown"

        if size > max_chunk_size:
            logging.debug("Too big, splitting the dump into chunks")
            utils.split_big_chunk(agent, base, size, max_chunk_size, outdir, filename)
            continue
        utils.dump_to_file(agent, base, size, outdir, filename)
        idx += 1
        utils.print_progress(
            idx, len(mem_ranges), prefix="Progress:", suffix="Complete", max_percent=50
        )
    logging.info("Done")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt as ex:
        sys.exit()
