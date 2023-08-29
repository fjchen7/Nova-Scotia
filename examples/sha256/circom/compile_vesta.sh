#!/bin/bash

if [[ -z "$1" ]]; then
  echo "Right Usage: ./compile_vesta.sh <count_per_step>"
  exit 1
fi
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
sed -i "s/component main.*/component main { public [step_in] } = Main($1);/" $SCRIPT_DIR/sha256_test_nova.circom
circom $SCRIPT_DIR/sha256_test_nova.circom --r1cs --wasm --sym --c --output $SCRIPT_DIR/ --prime vesta
#circom $SCRIPT_DIR/sha256_test_nova.circom --r1cs --wasm --sym --c --output $SCRIPT_DIR/ --prime pallas

#Doesn't work on M1, using WASM instead
#cd examples/sha256/circom/toy_cpp && make

# NOTE: This is just one step of the computation
# Full computation happens inside sha256_wasm.rs
(cd $SCRIPT_DIR/sha256_test_nova_js && node generate_witness.js sha256_test_nova.wasm ../input_32_first_step.json output.wtns)

# Doesn't work on M1
#(cd ./examples/sha256/circom/sha256_test_nova_cpp && make)
