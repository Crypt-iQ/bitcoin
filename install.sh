#!/bin/bash

# Assumes AFLPlusPlus built with nyx option and is at /root/AFLPlusPlus, assumes we are called at /root/bitcoin
export CC=/root/AFLplusplus/afl-clang-fast
export CXX=/root/AFLplusplus/afl-clang-fast++
export LD=/root/AFLplusplus/afl-clang-fast

cmake -B build_fuzz -DBUILD_FOR_FUZZING=ON -DENABLE_HARDENING=OFF -DAPPEND_CPPFLAGS="-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -DSNAPSHOT_FUZZ"
cmake --build build_fuzz -j16

export CC=
export CXX=
export LD=

# Create nyx_bitcoin_agent.so
clang-19 -fPIC -D_GNU_SOURCE -DNO_PT_NYX agent.c -ldl -I. -shared -o nyx_bitcoin_agent.so

# Remove polluted share directory if it exists. Then create the share directory.
rm -r /tmp/fuzzsharedir
mkdir /tmp/fuzzsharedir

# Create the share directory.
python3 ./create_sharedir.py --dir=/tmp/fuzzsharedir --target=cmpctblock --binary=build_fuzz/bin/fuzz

# Build nyx tools
# TODO

# Assumes nyx tools are built.
cp /root/AFLplusplus/nyx_mode/packer/packer/linux_x86_64-userspace/bin64/* /tmp/fuzzsharedir
python3 /root/AFLplusplus/nyx_mode/packer/packer/nyx_config_gen.py /tmp/fuzzsharedir Kernel -m 4096

# Copy over fuzz and nyx_bitcoin_agent.so.
cp build_fuzz/bin/fuzz /tmp/fuzzsharedir/
cp nyx_bitcoin_agent.so /tmp/fuzzsharedir/

# Remove polluted /tmp/out if it exists
rm -r /tmp/out

# Do we need to set:
# - AFL_SKIP_CPUFREQ=1
# - AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1

# Add sample entry to /tmp/in
# TODO

# Assumes entry in /tmp/in
AFL_PATH=/root/AFLplusplus afl-fuzz -X -i /tmp/in -o /tmp/out -- /tmp/fuzzsharedir
