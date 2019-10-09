# pylint: disable = line-too-long, too-many-lines, no-name-in-module, missing-docstring, too-many-return-statements, anomalous-backslash-in-string, too-many-branches, no-self-use, unused-wildcard-import, wildcard-import, fixme, too-many-statements, invalid-name, broad-except, too-many-arguments
import sys
import logging
import os
from io import open


def print_progress(times, total, prefix='', suffix='', decimals=2, max_percent=100):
    """
    Progress max_percent function.
    Stolen from some SO thread I forgot
    """
    filled = int(round(max_percent * times / float(total)))
    percents = round(100.00 * (times / float(total)), decimals)
    max_percent = '#' * filled + '-' * (max_percent - filled)
    print('{} [{}] {}{} {}\r'.format(
        prefix, max_percent, percents, '%', suffix))
    sys.stdout.flush()
    if times == total:
        print("\n")


def frida_on_message(message, data):
    """
    Method to receive messages from Javascript API calls
    """
    print("[frida_on_message] message:", message, "data:", data)


def dump_to_file(agent, base, size, outdir):
    """
    Reading bytes from session and saving it to a file
    """
    try:
        filename = str(base) + '_dump.data'
        dump = agent.read_memory(base, size)
        fp = open(os.path.join(outdir, filename), 'wb')
        fp.write(dump)
        fp.close()
    except Exception as e:
        logging.error("[!] %s", str(e))
        logging.error("Oops, memory access violation!")


def split_big_chunk(agent, base, size, max_size, directory):
    times = size // max_size
    diff = size % max_size

    if diff == 0:
        logging.debug("Number of chunks: %d", times+1)
    else:
        logging.debug("Number of chunks: %d", times)

    cur_base = int(base, 0)
    for _ in range(int(times)):
        logging.debug("Save bytes: 0x%X till 0x%X",
                      int(cur_base), int(cur_base+max_size))
        dump_to_file(agent, cur_base, max_size, directory)
        cur_base = cur_base + max_size

    if diff != 0:
        logging.debug("Save bytes: 0x%x till 0x%x",
                      int(cur_base), int(cur_base + diff))
        dump_to_file(agent, cur_base, diff, directory)
