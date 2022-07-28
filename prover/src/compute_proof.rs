use bus_mapping::circuit_input_builder::BuilderClient;
use bus_mapping::rpc::GethClient;
use ethers_providers::Http;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::{
    pairing::bn256::{Fr, G1Affine},
    plonk::*,
    poly::commitment::Params,
    transcript::{Blake2bWrite, Challenge255},
};
use rand::rngs::OsRng;

use std::str::FromStr;
use std::time::Instant;

use eth_types::geth_types;
use eth_types::Bytes;
use strum::IntoEnumIterator;
use zkevm_circuits::evm_circuit::witness::Block;
use zkevm_circuits::evm_circuit::{table::FixedTableTag, witness::block_convert};
use zkevm_circuits::super_circuit::SuperCircuit;
use zkevm_circuits::tx_circuit::Curve;
use zkevm_circuits::tx_circuit::Group;
use zkevm_circuits::tx_circuit::Secp256k1Affine;
use zkevm_circuits::tx_circuit::TxCircuit;

use crate::structs::Proofs;

const BLOCK_GAS_LIMIT: usize = 2_000_000;
const MAX_TXS: usize = 1;
const MAX_CALLDATA_TX: usize = 2048;
const NUM_BLINDING_ROWS: usize = 7 - 1;

fn build_circuit(
    k: u32,
    block: Block<Fr>,
    txs: Vec<geth_types::Transaction>,
) -> SuperCircuit<Fr, MAX_TXS, MAX_CALLDATA_TX> {
    let num_rows = 1 << k;
    let chain_id = block.context.chain_id;
    let aux_generator = <Secp256k1Affine as CurveAffine>::CurveExt::random(OsRng).to_affine();
    let tx_circuit = TxCircuit::new(aux_generator, block.randomness, chain_id.as_u64(), txs);

    SuperCircuit::<Fr, MAX_TXS, MAX_CALLDATA_TX> {
        block,
        fixed_table_tags: FixedTableTag::iter().collect(),
        tx_circuit,
        bytecode_size: num_rows - NUM_BLINDING_ROWS,
    }
}

// TODO: can this be pre-generated to a file?
// related
// https://github.com/zcash/halo2/issues/443
// https://github.com/zcash/halo2/issues/449
/// Compute a static proving key for SuperCircuit
/// TODO: should be correctly derived based on `K`.
pub fn gen_static_key(
    params: &Params<G1Affine>,
) -> Result<ProvingKey<G1Affine>, Box<dyn std::error::Error>> {
    use bus_mapping::circuit_input_builder::Block;
    use bus_mapping::state_db::CodeDB;
    use eth_types::Word;
    use eth_types::U256;

    let history_hashes = vec![Word::zero(); 256];
    let mut eth_block: eth_types::Block<eth_types::Transaction> = eth_types::Block::default();
    eth_block.number = Some(history_hashes.len().into());
    eth_block.base_fee_per_gas = Some(0.into());
    eth_block.hash = Some(eth_block.parent_hash);
    eth_block.gas_limit = BLOCK_GAS_LIMIT.into();
    let txs = eth_block
        .transactions
        .iter()
        .map(geth_types::Transaction::from_eth_tx)
        .collect();

    let code_db = CodeDB::new();
    let chain_id = U256::from(99);
    let block = Block::new(chain_id, history_hashes, &eth_block)?;
    let block = block_convert(&block, &code_db);

    let circuit = build_circuit(params.k, block, txs);
    let vk = keygen_vk(params, &circuit)?;
    let pk = keygen_pk(params, vk, &circuit)?;

    Ok(pk)
}

/// Gathers debug trace(s) from `rpc_url` for block `block_num` with `params`
/// created via the `gen_params` tool.
/// Expects a go-ethereum node with debug & archive capabilities on `rpc_url`.
pub async fn compute_proof(
    params: &Params<G1Affine>,
    block_num: &u64,
    rpc_url: &str,
) -> Result<Proofs, Box<dyn std::error::Error>> {
    // request & build the inputs for the circuits
    let time_started = Instant::now();
    let txs;
    let block;
    {
        let url = Http::from_str(rpc_url)?;
        let geth_client = GethClient::new(url);
        let builder = BuilderClient::new(geth_client).await?;
        let (eth_block, geth_traces) = builder.get_block(*block_num).await?;

        txs = eth_block
            .transactions
            .iter()
            .map(geth_types::Transaction::from_eth_tx)
            .collect();

        let access_set = builder.get_state_accesses(&eth_block, &geth_traces)?;
        let (proofs, codes) = builder.get_state(*block_num, access_set).await?;
        let (state_db, code_db) = builder.build_state_code_db(proofs, codes);
        let builder = builder.gen_inputs_from_state(state_db, code_db, &eth_block, &geth_traces)?;
        block = block_convert(&builder.block, &builder.code_db);
    }

    let evm_proof = {
        let circuit = build_circuit(params.k, block, txs);
        let pk = gen_static_key(params)?;
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        // TODO: add instances in the future - leave it empty to make testing 'possible'
        create_proof(params, &pk, &[circuit], &[], OsRng, &mut transcript)?;

        transcript.finalize()
    };

    let ret = Proofs {
        evm_proof: evm_proof.into(),
        state_proof: Bytes::default(),
        duration: Instant::now().duration_since(time_started).as_millis() as u64,
    };

    Ok(ret)
}
