import argparse
import os
import sys
import subprocess
import shutil

def create_sharedir():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description='''Create the nyx share dir for Bitcoin Core snapshot fuzzing''',
    )

    parser.add_argument(
        "--dir",
        help="Full path to the share dir",
        required=True,
    )
    parser.add_argument(
        "--target",
        help="Name of the Bitcoin Core target you want to fuzz",
        required=True,
    )
    parser.add_argument(
        "--binary",
        help="Path to the Bitcoin Core fuzz binary",
        required=True,
    )

    args = parser.parse_args()

    if not os.path.exists(args.dir):
        print("Share dir does not exist", file=sys.stderr)
        exit(1)

    deps = copy_shared_libs(binary_path=args.binary, share_dir=args.dir)

    deps += ["fuzz", "nyx_bitcoin_agent.so"]

    create_fuzz_no_pt(target=args.target, share_dir=args.dir, dependencies=deps)

# Use `lddtree` to figure out which dependencies are dynamically linked
def copy_shared_libs(binary_path: str, share_dir: str) -> list[str]:
    res = subprocess.run(
        ["lddtree", binary_path],
        capture_output=True,
        text=True,
    )

    if res.returncode != 0:
        print("lddtree error:", file=sys.stderr)
        print(res.stderr, file=sys.stderr)
        exit(1)

    lines = res.stdout.splitlines()
    # Skip first 
    lines = lines[1:]

    dependencies = []
    for line in lines:
        # libsome.so => /path/to/some/lib.so
        name_and_path = line.split("=>")
        assert(len(name_and_path) == 2)
        name = name_and_path[0].strip()
        path = name_and_path[1].strip()

        shutil.copyfile(path, os.path.join(share_dir, name))

        dependencies.append(name)

    return dependencies

def create_fuzz_no_pt(target: str, share_dir: str, dependencies: list[str]):
    fuzz_no_pt_lines = []

    fuzz_no_pt_lines.append("chmod +x hget")
    fuzz_no_pt_lines.append("cp hget /tmp")
    fuzz_no_pt_lines.append("cd /tmp")
    fuzz_no_pt_lines.append("echo 0 > /proc/sys/kernel/randomize_va_space")
    fuzz_no_pt_lines.append("echo 0 > /proc/sys/kernel/printk")

    fuzz_no_pt_lines.append("./hget hcat_no_pt hcat")
    fuzz_no_pt_lines.append("./hget habort_no_pt habort")

    for dep in dependencies:
        fuzz_no_pt_lines.append(f'./hget {dep} {dep}')

    for make_executable in ["habort", "hcat", "fuzz", "nyx_bitcoin_agent.so", "ld-linux-x86-64.so.2"]:
        fuzz_no_pt_lines.append(f'chmod +x {make_executable}') 

    fuzz_no_pt_lines.append(f'export FUZZ={target}')
    fuzz_no_pt_lines.append('export __AFL_DEFER_FORKSRV=1')
    fuzz_no_pt_lines.append(f'LD_LIBRARY_PATH=/tmp LD_BIND_NOW=1 LD_PRELOAD=nyx_bitcoin_agent.so ./fuzz > output.txt 2>&1')

    fuzz_no_pt_lines.append("cat output.txt | ./hcat")
    fuzz_no_pt_lines.append('./habort "target has terminated without initializing the fuzzing agent ..."')

    fuzz_no_pt_file = open(os.path.join(share_dir, "fuzz_no_pt.sh"), "w")
    fuzz_no_pt_file.writelines(map(lambda line: f'{line}\n', fuzz_no_pt_lines))
    fuzz_no_pt_file.close()

if __name__ == '__main__':
    create_sharedir()
