#[macro_export]
macro_rules! match_circuit_params {
    ($gas_used:expr, $on_match:expr, $on_error:expr) => {
        match $gas_used {
            0..=100000 => {
                const BLOCK_GAS_LIMIT: usize = 100000;
                const MAX_TXS: usize = 4;
                const MAX_CALLDATA: usize = 19750;
                const MAX_BYTECODE: usize = 26333;
                const MIN_K: usize = 20;
                $on_match
            }
            100001..=200000 => {
                const BLOCK_GAS_LIMIT: usize = 200000;
                const MAX_TXS: usize = 9;
                const MAX_CALLDATA: usize = 44750;
                const MAX_BYTECODE: usize = 59666;
                const MIN_K: usize = 21;
                $on_match
            }
            200001..=500000 => {
                const BLOCK_GAS_LIMIT: usize = 500000;
                const MAX_TXS: usize = 23;
                const MAX_CALLDATA: usize = 119750;
                const MAX_BYTECODE: usize = 159666;
                const MIN_K: usize = 22;
                $on_match
            }
            500001..=1000000 => {
                const BLOCK_GAS_LIMIT: usize = 1000000;
                const MAX_TXS: usize = 47;
                const MAX_CALLDATA: usize = 244750;
                const MAX_BYTECODE: usize = 326333;
                const MIN_K: usize = 23;
                $on_match
            }

            _ => $on_error,
        }
    };
}
