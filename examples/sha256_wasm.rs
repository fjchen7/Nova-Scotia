#![allow(warnings)]

use ark_std::{end_timer, start_timer};

use std::{collections::HashMap, env, env::current_dir, time::Instant};

use ff::derive::bitvec::vec;
use ff::PrimeField;
use nova_scotia::{
    circom::{circuit::CircomCircuit, reader::load_r1cs},
    create_public_params, create_recursive_circuit, FileLocation, F, S,
};
// Ignore create_recursive_circuit
pub type G1 = pasta_curves::pallas::Point;
pub type G2 = pasta_curves::vesta::Point;
pub type F1 = F<G1>;
pub type F2 = F<G2>;
pub type S1 = S<G1>;
pub type S2 = S<G2>;

use nova_snark::{
    // parallel_prover::{FoldInput, NovaTreeNode, PublicParams},
    traits::{circuit::TrivialTestCircuit, Group},
    CompressedSNARK,
};
use num_bigint::BigInt;
use num_traits::Num;
use serde::{Deserialize, Serialize};
use serde_json::json;

use sha2::{Digest, Sha256};

fn gen_nth_sha256_hash(n: usize) -> Vec<u8> {
    let mut hash = vec![0; 32];
    for _ in 0..n {
        let new_hash = Sha256::digest(&hash);
        hash = new_hash.as_slice().to_owned();
    }
    hash
}

static SCHEME: &str = "sha256_test_nova";
fn recursive_hashing(depth: usize) {
    println! {"Using recursive depth: {:?} times depth_per_fold in circuit (default 10 or 100, check yourself! :D)", depth};

    let iteration_count = depth;
    let root = current_dir().unwrap();

    let circuit_file = root.join(format!("./examples/sha256/circom/{}.r1cs", SCHEME));
    let r1cs = load_r1cs::<G1, G2>(&FileLocation::PathBuf(circuit_file));
    let witness_generator_wasm = root.join(format!(
        "./examples/sha256/circom/{}_js/{}.wasm",
        SCHEME, SCHEME
    ));

    let mut in_vector = vec![];
    for i in 0..depth {
        in_vector.push(gen_nth_sha256_hash(i));
    }

    // println!("100th recursive SHA256 hash: {:?}", gen_nth_sha256_hash(100));

    let step_in_vector = vec![0; 32];

    let mut private_inputs = Vec::new();
    for i in 0..iteration_count {
        let mut private_input = HashMap::new();
        private_input.insert("in".to_string(), json!(in_vector[i]));
        private_inputs.push(private_input);
    }

    let start_public_input = step_in_vector
        .into_iter()
        .map(|x| F1::from(x))
        .collect::<Vec<_>>();

    let pp = create_public_params(r1cs.clone());

    println!(
        "Number of constraints per step (primary circuit): {}",
        pp.num_constraints().0
    );
    println!(
        "Number of constraints per step (secondary circuit): {}",
        pp.num_constraints().1
    );

    println!(
        "Number of variables per step (primary circuit): {}",
        pp.num_variables().0
    );
    println!(
        "Number of variables per step (secondary circuit): {}",
        pp.num_variables().1
    );

    // create a recursive SNARK
    let timer_create_proof = start_timer!(|| "Create RecursiveSNARK");
    let recursive_snark = create_recursive_circuit(
        FileLocation::PathBuf(witness_generator_wasm),
        r1cs,
        private_inputs,
        start_public_input.clone(),
        &pp,
    )
    .unwrap();
    end_timer!(timer_create_proof);

    // TODO: empty?
    let z0_secondary = vec![<G2 as Group>::Scalar::zero()];

    // verify the recursive SNARK
    println!("Verifying a RecursiveSNARK...");
    let timer_verify_snark = start_timer!(|| "verify SNARK");
    let start = Instant::now();
    let res = recursive_snark.verify(
        &pp,
        iteration_count,
        start_public_input.as_slice(),
        z0_secondary.as_slice(),
    );
    assert!(res.is_ok());

    end_timer!(timer_verify_snark);

    // produce a compressed SNARK
    let timer_gen_compressed_snark =
        start_timer!(|| "Generate a CompressedSNARK using Spartan with IPA-PC");
    let start = Instant::now();
    let (pk, vk) = CompressedSNARK::<_, _, _, _, S1, S2>::setup(&pp).unwrap();
    let res = CompressedSNARK::<_, _, _, _, S1, S2>::prove(&pp, &pk, &recursive_snark);
    assert!(res.is_ok());
    let compressed_snark = res.unwrap();
    end_timer!(timer_gen_compressed_snark);

    let timer_verify_compressed_snark = start_timer!(|| "Verify CompressedSNARK");
    let start = Instant::now();
    let res = compressed_snark.verify(
        &vk,
        iteration_count,
        start_public_input.clone(),
        z0_secondary,
    );
    end_timer!(timer_verify_compressed_snark);

    assert!(res.is_ok());
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let k: usize = args[1].parse().unwrap();

    // NOTE: Toggle here
    recursive_hashing(k);
}
