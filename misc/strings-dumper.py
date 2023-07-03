# This script takes a target directory filled with .data files, runs `strings` on each and dumps them in a log file.
# It also takes a keyword to filter out files that do not contain the keyword.
# Usage: python3 strings-dumper.py <target_dir> <target_log_file> <keyword_in_data_file>
# Example: python3 strings-dumper.py dump/ dump/strings.log "unknown"
import sys
import os
import subprocess


def main():
    target_dir = sys.argv[1]
    target_log_file = sys.argv[2]
    keyword_in_data_file = sys.argv[3]

    if os.path.exists(target_log_file):
        os.remove(target_log_file)

    for root, _, files in os.walk(target_dir):
        total = len(files)
        for idx, file in enumerate(files):
            if keyword_in_data_file not in file:
                print("[{}/{}] {} (skipped)".format(idx + 1, total, file))
                continue

            print("[{}/{}] {}".format(idx + 1, total, file))
            if not file.endswith(".data"):
                continue
            file_path = os.path.join(root, file)
            with open(target_log_file, "a") as f:
                f.write("strings {}\n".format(file_path))
                f.write("-" * 80 + "\n")

            out = subprocess.check_output(
                "strings {}".format(file_path), shell=True
            )
            if out.strip() == b"":
                continue

            subprocess.call(
                "strings {}".format(file_path),
                shell=True,
                stdout=open(target_log_file, "a"),
                stderr=open(target_log_file, "a"),
            )
            with open(target_log_file, "a") as f:
                f.write("\n\n")


if __name__ == "__main__":
    main()
