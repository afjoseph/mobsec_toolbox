#!/usr/bin/env python3

# pylint: disable = line-too-long, too-many-lines, no-name-in-module, missing-docstring, too-many-return-statements, anomalous-backslash-in-string, too-many-branches, no-self-use, unused-wildcard-import, wildcard-import, fixme, too-many-statements, invalid-name, broad-except, redefined-outer-name, global-statement
import textwrap
import json
import sys
import os
import argparse
import codecs
import logging

import r2pipe
import frida
import frida.core

HOOK_LIBRARY = ""
HOOK_ADDR = ""
R2 = None
SESSION = None


def on_message(json_message, _):
    if "payload" not in json_message:
        raise Exception(
            "Could not parse Frida agent message:\n%s" % json_message)

    msg_payload = json_message["payload"]
    if 'calls' in msg_payload:
        json_calls = msg_payload.split(':')[1].strip()
        calls = json.loads(json_calls)
        if not calls:
            logging.info("No calls in the PLT section occurred for this ADDR")
            sys.exit()

        logging.info("Tracing %s@%s concluded with %d calls:",
                     HOOK_ADDR, HOOK_LIBRARY, len(calls))
        for call in calls:
            func_name = R2.cmdj("afij {}".format(call))
            if not func_name or "name" not in func_name[0]:
                print("\t{} -> UNDEFINED".format(call))
                continue

            print("\t{} -> {}".format(call, func_name[0]["name"]))
        logging.info("Done. You can exit the script now...")
        SESSION.detach()


def get_plt_addrs(r2):
    logging.info("Retrieving PLT section...")
    plt_cmd = r2.cmd("iS~-r-x .plt$")
    if not plt_cmd:
        raise Exception("No PLT section in the binary")

    plt_cmd_arr = plt_cmd.split()
    plt_start = int(plt_cmd_arr[1], 16)
    plt_finish = plt_start + int(plt_cmd_arr[2])
    logging.info(".plt [0x%X] -> [0x%X]", plt_start, plt_finish)

    return plt_start, plt_finish


def main():
    parser = argparse.ArgumentParser(
        prog="native_func_hooker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent(""))

    parser.add_argument("-p", "--process",
                        help="the process being booked")
    parser.add_argument("-l", "--library",
                        help="the library to hook")
    parser.add_argument("-a", "--addr",
                        help="the the address to hook")
    parser.add_argument("-b", "--binary",
                        help="The binary to work with")
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='verbose')
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(format='%(levelname)s:%(message)s',
                            level=logging.DEBUG)
    else:
        logging.basicConfig(
            format='%(levelname)s:%(message)s', level=logging.INFO)

    agent_code = ""
    try:
        curr_dir = os.path.dirname(os.path.abspath(__file__))
        agent_path = os.path.join(curr_dir, "agent.js")
        # with open(agent_path, mode="r", encoding="utf-8") as fp:
        with codecs.open(agent_path, 'r', 'utf-8') as fp:
            agent_code = fp.read()
            if not agent_code:
                raise IOError("File is empty")
    except IOError:
        logging.error("Couldn't read agent.js")
        sys.exit()

    global HOOK_LIBRARY
    global HOOK_ADDR
    HOOK_LIBRARY = args.library
    HOOK_ADDR = int(args.addr, 16)

    logging.info("Analyzing with R2...")
    global R2
    R2 = r2pipe.open(args.binary)
    R2.cmd("aa")
    plt_start, plt_finish = get_plt_addrs(R2)

    try:
        logging.info("Prepping Frida...")
        device = frida.get_usb_device()
        pid = device.spawn([args.process])
        global SESSION
        SESSION = device.attach(pid)
        SESSION.enable_jit()
        script = SESSION.create_script(agent_code)
        script.on('message', on_message)
        script.load()

        logging.info("Resuming process...")

        logging.info("Hooking library loaders...")
        script.exports.loaders(HOOK_LIBRARY, HOOK_ADDR, plt_start, plt_finish)
        logging.info("Awaiting hook callbacks...")

        device.resume(args.process)
        sys.stdin.read()
    except Exception as e:
        logging.error("Frida failed to connect to app with err: [%s]", str(e))
        sys.exit()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit()
