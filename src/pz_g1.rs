//! PZ-G1 research prototype.  This is a separate, explicitly experimental
//! consensus/economic state machine; legacy Phase Zero fixtures remain intact.
//! It selects mechanisms from SPECIFICATION_ALTERNATIVE.md §§23-26.
//!
//! WARNING: tests, real VRF/KES primitives and a deterministic fork comparator
//! do not constitute a transfer of the Ouroboros Genesis security theorem.
//! Epoch entropy, historical peer selection, incentives and honest stake
//! distribution require further independent analysis.
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub mod economy;
pub mod consensus;
// Experiment 021: separate read-only source Genesis/GSM/LoE/GDD research lens.
// It does not replace fork choice or confer current-root authority.
pub mod genesis_sync_trial;
// Experiment 022: untrusted wire-level ChainSync-like header observation.
pub mod chain_sync_observe;
// Experiment 023: isolated event-driven source-assumption/LoP/GDD trial.
pub mod genesis_event_trial;
pub mod codec;
pub mod proofs;
pub use economy::*;
pub use consensus::*;

pub type Hash = [u8; 32];
pub type Owner = [u8; 32];
pub const BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Error {
    Malformed = 1, Unauthorized = 2, BadNonce = 3,
    Funds = 4, Unknown = 5, Expired = 6, Premature = 7,
    Duplicate = 8, BadEvidence = 9, Limit = 10, Overflow = 11,
    InvalidBlock = 12, InvalidProof = 13, FrozenEra = 14, Unavailable = 15,
}
pub type PzResult<T> = std::result::Result<T, Error>;
pub fn digest(domain: &[u8], parts: &[&[u8]]) -> Hash {
    let mut h = Sha256::new();
    h.update((domain.len() as u64).to_le_bytes());
    h.update(domain);
    for part in parts {
        h.update((part.len() as u64).to_le_bytes());
        h.update(part);
    }
    h.finalize().into()
}
pub fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend((bytes.len() as u64).to_le_bytes());
    out.extend(bytes);
}
pub fn put_u64(out: &mut Vec<u8>, v: u64) { out.extend(v.to_le_bytes()); }
pub fn put_hash(out: &mut Vec<u8>, v: &Hash) { out.extend(v); }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Prices {
    pub per_byte: u64, pub per_signature: u64,
    pub per_core_step: u64, pub per_state_byte: u64,
    pub per_proof: u64, pub per_terminal: u64,
}
impl Prices {
    pub fn encode(&self, out: &mut Vec<u8>) {
        for n in [self.per_byte, self.per_signature, self.per_core_step,
                  self.per_state_byte, self.per_proof, self.per_terminal] {
            put_u64(out, n);
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Profile {
    pub network_salt: Hash,
    pub slot_seconds: u64,
    pub epoch_slots: u64,
    pub k_blocks: u64,
    pub s_slots: u64,
    pub f_num: u64,
    pub f_den: u64,
    pub horizon: u64,
    pub issue_base: u64,
    pub issue_data: u64,
    pub max_block_events: usize,
    pub max_action_bytes: usize,
    pub max_core_steps: u64,
    pub max_due_per_block: usize,
    pub max_archive_bytes: usize,
    pub prices: Prices,
    pub core_digest: Hash,
    pub runtime_digest: Hash,
}
impl Profile {
    pub fn validate(&self) -> PzResult<()> {
        if self.slot_seconds == 0 || self.epoch_slots < 3 ||
           self.horizon == 0 || self.horizon > 128 ||
           self.k_blocks == 0 || self.s_slots == 0 ||
           self.k_blocks > self.horizon || self.s_slots > self.horizon ||
           self.f_num == 0 ||
           self.f_num > self.f_den || self.f_den == 0 ||
           self.max_block_events == 0 || self.max_block_events > 64 ||
           self.max_action_bytes == 0 || self.max_action_bytes > 65_536 ||
           self.max_core_steps == 0 || self.max_core_steps > 1_000_000 ||
           self.max_due_per_block == 0 || self.max_due_per_block > 4096 ||
           self.max_archive_bytes == 0 || self.max_archive_bytes > 65_536 ||
           self.issue_base == 0 || self.issue_data == 0 ||
           self.prices.per_byte == 0 || self.prices.per_signature == 0 ||
           self.prices.per_terminal == 0 { return Err(Error::Malformed); }
        Ok(())
    }
    pub fn encode(&self, out: &mut Vec<u8>) {
        put_hash(out, &self.network_salt);
        for x in [self.slot_seconds,self.epoch_slots,self.k_blocks,self.s_slots,
                  self.f_num,self.f_den,self.horizon,self.issue_base,self.issue_data,
                  self.max_block_events as u64,self.max_action_bytes as u64,
                  self.max_core_steps,self.max_due_per_block as u64,
                  self.max_archive_bytes as u64] {put_u64(out, x);}
        self.prices.encode(out);
        put_hash(out, &self.core_digest);
        put_hash(out, &self.runtime_digest);
    }
    pub fn epoch(&self, slot: u64) -> u64 { slot / self.epoch_slots }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Credential {
    pub id: Hash,
    pub owner: Owner,
    pub operator: Owner,
    pub vrf_public: Hash,
    pub kes_public: Vec<u8>,
    pub amount: u64,
    pub commission_bps: u16,
    pub exit_epoch: Option<u64>,
    pub exit_requested_height: Option<u64>,
}
impl Credential {
    pub fn make_id(owner: &Owner, vrf: &Hash, kes: &[u8]) -> Hash {
        digest(b"AlgoX/PZ-G1/credential/v1", &[owner, vrf, kes])
    }
    pub fn validate(&self) -> PzResult<()> {
        if self.amount == 0 || self.commission_bps as u64 > BPS ||
           self.kes_public.is_empty() || self.kes_public.len() > 2048 ||
           self.id != Self::make_id(&self.owner, &self.vrf_public, &self.kes_public) {
            return Err(Error::Malformed);
        }
        Ok(())
    }
    pub fn encode(&self, out: &mut Vec<u8>) {
        for x in [&self.id,&self.owner,&self.operator,&self.vrf_public] {put_hash(out,x);}
        put_bytes(out, &self.kes_public);
        put_u64(out,self.amount);
        out.extend(self.commission_bps.to_le_bytes());
        match self.exit_epoch {Some(x)=>{out.push(1);put_u64(out,x)},None=>out.push(0)}
        match self.exit_requested_height {Some(x)=>{out.push(1);put_u64(out,x)},None=>out.push(0)}
    }
}

#[derive(Clone, Debug)]
pub struct Genesis {
    /// None preserves original canonical v1 bytes. Some is an opt-in, tagged
    /// version-2 research genesis and becomes part of its immutable ID.
    pub activation_unix_ms: Option<u64>,
    pub profile: Profile,
    pub accounts: BTreeMap<Owner,u64>,
    pub locked: Vec<Credential>,
}
impl Genesis {
    pub fn validate(&self) -> PzResult<()> {
        self.profile.validate()?;
        if let Some(t0)=self.activation_unix_ms {
            let slot_ms=self.profile.slot_seconds.checked_mul(1_000)
                .ok_or(Error::Overflow)?;
            let span=(self.profile.horizon+1).checked_mul(slot_ms)
                .ok_or(Error::Overflow)?;
            if t0==0 || t0.checked_add(span).is_none() {
                return Err(Error::Malformed);
            }
        }
        if self.accounts.len() > 10_000 || self.locked.len() > 1024 {
            return Err(Error::Limit);
        }
        let mut total = 0u128;
        for balance in self.accounts.values() {total += *balance as u128;}
        let mut ids=BTreeSet::new();
        for c in &self.locked {
            c.validate()?;
            if !ids.insert(c.id) { return Err(Error::Duplicate); }
            total += c.amount as u128;
        }
        if total == 0 || total > u64::MAX as u128 {return Err(Error::Overflow);}
        if self.locked.is_empty() {return Err(Error::Malformed);}
        Ok(())
    }
    /// Derive the canonical slot solely from an authenticated v2 genesis T0
    /// and the host clock. Peer gossip and controller RUN timestamps are not
    /// authority. The host clock's accuracy remains an external assumption.
    pub fn activated_slot_at_ms(&self, unix_ms:u64)->PzResult<Option<u64>> {
        let t0=self.activation_unix_ms.ok_or(Error::Unavailable)?;
        if unix_ms<t0{return Ok(None);}
        let slot_ms=self.profile.slot_seconds.checked_mul(1_000)
            .ok_or(Error::Overflow)?;
        let slot=(unix_ms-t0)/slot_ms;
        Ok(Some(slot.checked_add(1).ok_or(Error::Overflow)?))
    }
    pub fn initial_supply(&self) -> PzResult<u64> {
        self.validate()?;
        let accounts=self.accounts.values().map(|x| *x as u128).sum::<u128>();
        let locks=self.locked.iter().map(|x| x.amount as u128).sum::<u128>();
        u64::try_from(accounts+locks).map_err(|_|Error::Overflow)
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut out=Vec::new();
        self.profile.encode(&mut out);
        put_u64(&mut out,self.accounts.len() as u64);
        for (owner,amount) in &self.accounts {put_hash(&mut out,owner);put_u64(&mut out,*amount);}
        let mut sorted=self.locked.clone();
        sorted.sort_by_key(|x|x.id);
        put_u64(&mut out,sorted.len() as u64);
        for stake in sorted {stake.encode(&mut out);}
        // The legacy v1 manifest has no trailer. A v2 activated manifest
        // carries an unambiguous fixed-size versioned T0 extension.
        if let Some(t0)=self.activation_unix_ms {
            out.extend(b"PZG1T0\x01");
            put_u64(&mut out,t0);
        }
        out
    }
    pub fn id(&self) -> Hash {
        let domain=if self.activation_unix_ms.is_some() {
            b"AlgoX/PZ-G1/activated-genesis/v2".as_slice()
        }else{b"AlgoX/PZ-G1/genesis/v1".as_slice()};
        digest(domain, &[&self.encode()])
    }
    /// Verify bytes from any untrusted mirror against the original immutable
    /// trust anchor before the host is allowed to instantiate downloaded Wasm.
    /// The host must ALSO reject unapproved imports/capabilities.
    pub fn authenticate_runtime(&self,bytes:&[u8])->PzResult<()>{
        const WASM_CORE:&[u8;8]=b"\0asm\x01\0\0\0";
        if bytes.len()>64*1024*1024 ||
           bytes.len()<WASM_CORE.len() ||
           &bytes[..WASM_CORE.len()]!=WASM_CORE {
            return Err(Error::Malformed);
        }
        let verified:Hash=Sha256::digest(bytes).into();
        if verified!=self.profile.runtime_digest {
            return Err(Error::InvalidProof);
        }
        Ok(())
    }
    /// The original deterministic sponsor/Core interpreter is separately
    /// pinned. This establishes byte identity only, never semantic truth.
    pub fn authenticate_core(&self,bytes:&[u8])->PzResult<()>{
        if bytes.is_empty() || bytes.len()>16*1024*1024 {
            return Err(Error::Limit);
        }
        let verified:Hash=Sha256::digest(bytes).into();
        if verified!=self.profile.core_digest {
            return Err(Error::InvalidProof);
        }
        Ok(())
    }
}

/// Fixed-width exact rational leadership comparison against the 64-bit VRF
/// prefix: q = y / 2^64, and q < 1-(1-f)^(stake/total).
/// Big integer exponentiation is intentionally bounded in this *research*
/// profile; no floating-point thresholds or modulo rounding are used.
/// It remains a 64-bit discretization, NOT the Ouroboros proof's abstract VRF.
pub fn wins(vrf_prefix: u64, stake:u64, total:u64, f_num:u64, f_den:u64) -> PzResult<bool> {
    use num_bigint::BigUint;
    if stake==0 || total==0 || stake>total || total>1024 ||
       f_den==0 || f_num==0 || f_num>f_den {return Err(Error::Limit);}
    if f_num==f_den {return Ok(true);}
    let a = BigUint::from(u64::MAX as u128 + 1 - vrf_prefix as u128);
    let space = BigUint::from(1u128 << 64);
    let den = BigUint::from(f_den);
    let one_minus = BigUint::from(f_den-f_num);
    Ok(a.pow(total as u32)*den.pow(stake as u32) >
       space.pow(total as u32)*one_minus.pow(stake as u32))
}
