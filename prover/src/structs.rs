#[derive(Debug, Clone, serde::Serialize)]
pub struct Proofs {
    pub state_proof: eth_types::Bytes,
    pub evm_proof: eth_types::Bytes,
}

#[derive(Debug, serde::Serialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
}

#[derive(Debug, serde::Serialize)]
pub struct JsonRpcResponseError {
    pub jsonrpc: String,
    pub id: serde_json::Value,
    pub error: JsonRpcError,
}

#[derive(Debug, serde::Serialize)]
pub struct JsonRpcResponse<T: serde::Serialize> {
    pub jsonrpc: String,
    pub id: serde_json::Value,
    pub result: T,
}

#[derive(Debug, serde::Deserialize)]
pub struct JsonRpcRequest<T: serde::Serialize> {
    pub id: serde_json::Value,
    pub method: String,
    pub params: T,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Witness {
    pub randomness: eth_types::U256,
    pub input: eth_types::Bytes,
}

#[derive(Debug, Default, Clone, Copy, serde::Deserialize)]
pub struct ProofRequestOptions {
    /// Setups parameters on the fly
    pub k: Option<u32>,
}
