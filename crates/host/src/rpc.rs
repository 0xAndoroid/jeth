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
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(120))
            .build();
        Self { endpoints, agent }
    }

    /// Call `method` on the first endpoint that answers with a `result`.
    /// Returns `(result, endpoint_used)`.
    pub fn call(&self, method: &str, params: Value) -> Result<(Value, String)> {
        let mut last_err = anyhow!("no endpoints configured");
        for endpoint in &self.endpoints {
            match self.call_one(endpoint, method, &params) {
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
        let resp: Value = self
            .agent
            .post(endpoint)
            .set("Content-Type", "application/json")
            .send_json(body)
            .with_context(|| format!("transport error on {endpoint}"))?
            .into_json()
            .context("invalid JSON response")?;

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
