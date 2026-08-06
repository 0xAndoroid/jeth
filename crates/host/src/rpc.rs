//! Minimal JSON-RPC client with ordered-endpoint failover.
//!
//! The free hosted endpoints serving `debug_executionWitness` are undocumented
//! passthroughs — treat every call as fallible and rotate through the list.

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use std::time::Duration;

/// Default Tier-1 endpoint list (live-verified 2026-08-06, PLAN.md §3).
pub const DEFAULT_ENDPOINTS: &[&str] = &[
    "https://docs-demo.quiknode.pro/",
    "https://ethereum.public.blockpi.network/v1/rpc/public",
];

pub struct RpcClient {
    endpoints: Vec<String>,
    agent: ureq::Agent,
}

impl RpcClient {
    pub fn new(endpoints: Vec<String>) -> Self {
        // Generous: a zeth-rpc-proxy witness rebuild re-executes the block against
        // upstream getProof/getCode and can take many minutes on free endpoints.
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(3600))
            .build();
        Self { endpoints, agent }
    }

    /// Call `method` on the first endpoint that answers with a `result`.
    /// Returns `(result, endpoint_used)`.
    pub fn call(&self, method: &str, params: Value) -> Result<(Value, String)> {
        self.call_validated(method, params, |v| Ok(v.clone()))
    }

    /// Like [`Self::call`], but an endpoint only counts as successful if `validate`
    /// accepts its result (e.g. witness shape varies by node implementation —
    /// a parse failure should fail over to the next endpoint).
    pub fn call_validated<T>(
        &self,
        method: &str,
        params: Value,
        validate: impl Fn(&Value) -> Result<T>,
    ) -> Result<(T, String)> {
        let mut last_err = anyhow!("no endpoints configured");
        for endpoint in &self.endpoints {
            match self
                .call_one(endpoint, method, &params)
                .and_then(|v| validate(&v))
            {
                Ok(result) => return Ok((result, endpoint.clone())),
                Err(e) => {
                    tracing::warn!("{method} failed on {endpoint}: {e:#}");
                    last_err = e;
                }
            }
        }
        Err(last_err.context(format!("{method}: all endpoints failed")))
    }

    fn call_one(&self, endpoint: &str, method: &str, params: &Value) -> Result<Value> {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        // Retry 429s with backoff (QuickNode's public demo endpoint is ~1 req/s).
        let mut attempts = 0;
        let resp: Value = loop {
            attempts += 1;
            match self
                .agent
                .post(endpoint)
                .set("Content-Type", "application/json")
                .send_json(body.clone())
            {
                Ok(resp) => break resp.into_json().context("invalid JSON response")?,
                Err(ureq::Error::Status(429, _)) if attempts < 5 => {
                    tracing::warn!("429 from {endpoint}, backing off {}s", 2 * attempts);
                    std::thread::sleep(Duration::from_secs(2 * attempts));
                }
                Err(e) => return Err(e).with_context(|| format!("transport error on {endpoint}")),
            }
        };

        if let Some(err) = resp.get("error") {
            bail!("rpc error: {err}");
        }
        match resp.get("result") {
            Some(Value::Null) | None => bail!("empty result"),
            Some(result) => Ok(result.clone()),
        }
    }
}

/// Decode a `0x…` hex quantity into u64.
pub fn parse_quantity(v: &Value) -> Result<u64> {
    let s = v.as_str().context("quantity not a string")?;
    u64::from_str_radix(s.trim_start_matches("0x"), 16).context("bad hex quantity")
}

/// Decode a `0x…` hex blob into bytes.
pub fn parse_hex_bytes(v: &Value) -> Result<Vec<u8>> {
    let s = v.as_str().context("hex blob not a string")?;
    alloy_primitives::hex::decode(s).context("bad hex blob")
}
