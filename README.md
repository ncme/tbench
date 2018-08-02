TBENCH - the tiny crypto benchmark for RIOT OS
=====

RIOT OS application for benchmarking tiny crypto implementations and curve model transformations.

## Usage

Run `TBENCH=0 make` to build the application without active benchmarks.
If this works you can choose to run the following suites:
   * TBENCH=1 tweetnacl
   * TBENCH=2 c25519
   * TBENCH=3 tinyDTLS/ecc
   * TBENCH=4 ref10
   * TBENCH=5 relic

For example to make and run the benchmarks for tweetnacl on a 'bluepill' board:

    TBENCH=0 make flash term BOARD=bluepill CPU_MODEL=stm32f103cb

## Requirements

RIOT Version 2018.04 or greater.
The environment variable `$RIOT_DIR` must be set to the base directory of a RIOT project instance.
Please refer to the official RIOT OS wiki on how to set up the build system for your machine.

## Supported Boards

This application was tested on the board `bluepill`.
The `native` build is also supported and configured for `x64 Linux`.