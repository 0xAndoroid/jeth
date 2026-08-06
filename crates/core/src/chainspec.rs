//! Minimal mainnet chain spec for guest use.
//!
//! `reth_chainspec::MAINNET` parses the full mainnet genesis JSON (~2 MB, incl. the
//! genesis allocation) at first use — dead weight inside a zkVM guest. This is a
//! no_std adaptation of zeth 0.3's `zeth-chainspec` (Apache-2.0, RISC Zero Inc.):
//! chain id + hardfork schedule + deposit contract + base-fee/blob params only.
//! Verified equivalent to reth's `MAINNET` for validation purposes by zeth's tests.

use alloc::{boxed::Box, collections::BTreeMap, string::String, vec::Vec};
use alloy_eips::{
    eip2124::{ForkFilter, ForkId, Head},
    eip7840::BlobParams,
    BlobScheduleBlobParams,
};
use alloy_genesis::Genesis;
use alloy_primitives::{address, Address, B256, U256};
use core::any::Any;
use core::fmt::{self, Debug, Display};
use reth_chainspec::{BaseFeeParams, Chain, DepositContract, EthChainSpec, Hardforks, NamedChain};
use reth_ethereum_forks::{mainnet, EthereumHardfork, EthereumHardforks, ForkCondition, Hardfork};
use reth_evm::eth::spec::EthExecutorSpec;
use reth_primitives_traits::Header;

const MAINNET_DEPOSIT_CONTRACT_ADDRESS: Address =
    address!("0x00000000219ab540356cbb839cbe05303d7705fa");

/// Ethereum mainnet specification (Fusaka-era: Osaka + BPO1/BPO2 blob schedules).
pub fn mainnet_spec() -> ChainSpec {
    ChainSpec {
        chain: NamedChain::Mainnet.into(),
        forks: EthereumHardfork::mainnet().into(),
        deposit_contract_address: Some(MAINNET_DEPOSIT_CONTRACT_ADDRESS),
        base_fee_params: BaseFeeParams::ethereum(),
        blob_params: BlobScheduleBlobParams::default().with_scheduled([
            (mainnet::MAINNET_BPO1_TIMESTAMP, BlobParams::bpo1()),
            (mainnet::MAINNET_BPO2_TIMESTAMP, BlobParams::bpo2()),
        ]),
    }
}

/// Minimal chain spec carrying only what stateless validation needs.
#[derive(Clone, Debug)]
pub struct ChainSpec {
    chain: Chain,
    forks: BTreeMap<EthereumHardfork, ForkCondition>,
    deposit_contract_address: Option<Address>,
    base_fee_params: BaseFeeParams,
    blob_params: BlobScheduleBlobParams,
}

impl Display for ChainSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.chain)
    }
}

impl EthereumHardforks for ChainSpec {
    fn ethereum_fork_activation(&self, fork: EthereumHardfork) -> ForkCondition {
        self.forks.get(&fork).copied().unwrap_or_default()
    }
}

impl EthExecutorSpec for ChainSpec {
    fn deposit_contract_address(&self) -> Option<Address> {
        self.deposit_contract_address
    }
}

impl Hardforks for ChainSpec {
    fn fork<H: Hardfork>(&self, fork: H) -> ForkCondition {
        if let Some(eth_fork) = (&fork as &dyn Any).downcast_ref::<EthereumHardfork>() {
            self.ethereum_fork_activation(*eth_fork)
        } else {
            ForkCondition::Never
        }
    }

    fn forks_iter(&self) -> impl Iterator<Item = (&dyn Hardfork, ForkCondition)> {
        self.forks
            .iter()
            .map(|(eth_fork, condition)| (eth_fork as &dyn Hardfork, *condition))
    }

    fn fork_id(&self, _: &Head) -> ForkId {
        unimplemented!()
    }

    fn latest_fork_id(&self) -> ForkId {
        unimplemented!()
    }

    fn fork_filter(&self, _: Head) -> ForkFilter {
        unimplemented!()
    }
}

impl EthChainSpec for ChainSpec {
    type Header = Header;

    fn chain(&self) -> Chain {
        self.chain
    }

    fn base_fee_params_at_timestamp(&self, _: u64) -> BaseFeeParams {
        self.base_fee_params
    }

    fn blob_params_at_timestamp(&self, timestamp: u64) -> Option<BlobParams> {
        if let Some(blob_param) = self
            .blob_params
            .active_scheduled_params_at_timestamp(timestamp)
        {
            Some(*blob_param)
        } else if self.is_osaka_active_at_timestamp(timestamp) {
            Some(self.blob_params.osaka)
        } else if self.is_prague_active_at_timestamp(timestamp) {
            Some(self.blob_params.prague)
        } else if self.is_cancun_active_at_timestamp(timestamp) {
            Some(self.blob_params.cancun)
        } else {
            None
        }
    }

    fn deposit_contract(&self) -> Option<&DepositContract> {
        unimplemented!()
    }

    fn genesis_hash(&self) -> B256 {
        unimplemented!()
    }

    fn prune_delete_limit(&self) -> usize {
        unimplemented!()
    }

    fn display_hardforks(&self) -> Box<dyn Display> {
        Box::new(String::from("jeth mainnet"))
    }

    fn genesis_header(&self) -> &Self::Header {
        unimplemented!()
    }

    fn genesis(&self) -> &Genesis {
        unimplemented!()
    }

    fn bootnodes(&self) -> Option<Vec<reth_network_peers::NodeRecord>> {
        None
    }

    fn final_paris_total_difficulty(&self) -> Option<U256> {
        if let ForkCondition::TTD {
            total_difficulty, ..
        } = self.ethereum_fork_activation(EthereumHardfork::Paris)
        {
            Some(total_difficulty)
        } else {
            None
        }
    }
}
