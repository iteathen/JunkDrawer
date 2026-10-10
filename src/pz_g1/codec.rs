//! Strict, length-bounded canonical network codec for the PZ-G1 research era.
//! The original trust anchor (expected Genesis id) must be supplied outside
//! untrusted byte retrieval. Round-trip identity prevents alternate encodings.
use super::{Hash,Owner,Profile,Prices,Genesis,Credential,Error,PzResult,put_u64};
use super::economy::{Action,SignedEvent,Outcome,EvidenceMode};
use super::consensus::{Block,ArchiveResponse,Chain};
use crate::{Reader,Program,BoundTest,Evidence};
use std::collections::BTreeMap;

struct Wire<'a>{data:&'a[u8],offset:usize}
impl<'a> Wire<'a>{
    fn new(data:&'a[u8])->Self{Self{data,offset:0}}
    fn bytes(&mut self,n:usize)->PzResult<&'a[u8]>{
        let end=self.offset.checked_add(n).ok_or(Error::Limit)?;
        if end>self.data.len(){return Err(Error::Malformed);}
        let s=&self.data[self.offset..end];self.offset=end;Ok(s)
    }
    fn u8(&mut self)->PzResult<u8>{Ok(self.bytes(1)?[0])}
    fn u16(&mut self)->PzResult<u16>{Ok(u16::from_le_bytes(self.bytes(2)?.try_into().unwrap()))}
    fn u64(&mut self)->PzResult<u64>{Ok(u64::from_le_bytes(self.bytes(8)?.try_into().unwrap()))}
    fn hash(&mut self)->PzResult<Hash>{Ok(self.bytes(32)?.try_into().unwrap())}
    fn sized(&mut self,max:usize)->PzResult<&'a[u8]>{
        let len=usize::try_from(self.u64()?).map_err(|_|Error::Limit)?;
        if len>max{return Err(Error::Limit);}
        self.bytes(len)
    }
    fn end(&self)->PzResult<()>{
        if self.offset==self.data.len(){Ok(())}else{Err(Error::Malformed)}
    }
}
impl Profile{
    fn read(r:&mut Wire<'_>)->PzResult<Self>{
        let network_salt=r.hash()?;
        let slot_seconds=r.u64()?;let epoch_slots=r.u64()?;
        let k_blocks=r.u64()?;let s_slots=r.u64()?;
        let f_num=r.u64()?;let f_den=r.u64()?;
        let horizon=r.u64()?;let issue_base=r.u64()?;let issue_data=r.u64()?;
        let max_block_events=usize::try_from(r.u64()?).map_err(|_|Error::Limit)?;
        let max_action_bytes=usize::try_from(r.u64()?).map_err(|_|Error::Limit)?;
        let max_core_steps=r.u64()?;
        let max_due_per_block=usize::try_from(r.u64()?).map_err(|_|Error::Limit)?;
        let max_archive_bytes=usize::try_from(r.u64()?).map_err(|_|Error::Limit)?;
        let prices=Prices{
            per_byte:r.u64()?,per_signature:r.u64()?,per_core_step:r.u64()?,
            per_state_byte:r.u64()?,per_proof:r.u64()?,per_terminal:r.u64()?,
        };
        let core_digest=r.hash()?;let runtime_digest=r.hash()?;
        let p=Self{network_salt,slot_seconds,epoch_slots,k_blocks,s_slots,
            f_num,f_den,horizon,issue_base,issue_data,max_block_events,
            max_action_bytes,max_core_steps,max_due_per_block,max_archive_bytes,
            prices,core_digest,runtime_digest};
        p.validate()?;Ok(p)
    }
}
impl Credential{
    fn read(r:&mut Wire<'_>)->PzResult<Self>{
        let id=r.hash()?;let owner=r.hash()?;let operator=r.hash()?;
        let vrf_public=r.hash()?;let kes_public=r.sized(2048)?.to_vec();
        let amount=r.u64()?;let commission_bps=r.u16()?;
        let exit_epoch=match r.u8()?{0=>None,1=>Some(r.u64()?),_=>return Err(Error::Malformed)};
        let exit_requested_height=match r.u8()?{
            0=>None,1=>Some(r.u64()?),_=>return Err(Error::Malformed)
        };
        let cred=Self{id,owner,operator,vrf_public,kes_public,amount,
            commission_bps,exit_epoch,exit_requested_height};
        cred.validate()?;Ok(cred)
    }
}
impl Genesis{
    pub fn decode(bytes:&[u8],expected_id:&Hash)->PzResult<Self>{
        if bytes.len()>250_000{return Err(Error::Limit);}
        let mut r=Wire::new(bytes);
        let profile=Profile::read(&mut r)?;
        let accounts_count=usize::try_from(r.u64()?).map_err(|_|Error::Limit)?;
        if accounts_count>10_000{return Err(Error::Limit);}
        let mut accounts=BTreeMap::new();
        let mut previous:Option<Hash>=None;
        for _ in 0..accounts_count{
            let owner=r.hash()?;
            if previous.is_some_and(|x|owner<=x){return Err(Error::Malformed);}
            previous=Some(owner);
            let value=r.u64()?;
            accounts.insert(owner,value);
        }
        let stake_count=usize::try_from(r.u64()?).map_err(|_|Error::Limit)?;
        if stake_count>1024{return Err(Error::Limit);}
        let mut locked=Vec::with_capacity(stake_count);
        let mut last:Option<Hash>=None;
        for _ in 0..stake_count {
            let c=Credential::read(&mut r)?;
            if last.is_some_and(|x|c.id<=x){return Err(Error::Malformed);}
            last=Some(c.id);
            locked.push(c);
        }
        let activation_unix_ms=if r.offset==bytes.len(){None}else{
            if r.bytes(7)?!=b"PZG1T0\x01"{return Err(Error::Malformed);}
            Some(r.u64()?)
        };
        r.end()?;
        let genesis=Self{profile,accounts,locked,activation_unix_ms};
        genesis.validate()?;
        if genesis.id()!=*expected_id || genesis.encode()!=bytes {
            return Err(Error::InvalidProof);
        }
        Ok(genesis)
    }
}
pub(super) fn decode_program(bytes:&[u8])->PzResult<Program>{
    let mut r=Reader::new(bytes);
    let p=r.program().map_err(|_|Error::Malformed)?;
    r.finished().map_err(|_|Error::Malformed)?;
    if p.encode()!=bytes{return Err(Error::Malformed);}
    Ok(p)
}
pub(super) fn decode_test(bytes:&[u8])->PzResult<BoundTest>{
    let mut r=Reader::new(bytes);
    let t=r.bound_test().map_err(|_|Error::Malformed)?;
    r.finished().map_err(|_|Error::Malformed)?;
    let mut encoding=Vec::new();t.encode(&mut encoding);
    if encoding!=bytes{return Err(Error::Malformed);}
    Ok(t)
}
fn decode_evidence(bytes:&[u8])->PzResult<Evidence>{
    let mut r=Reader::new(bytes);
    let e=Evidence::decode(&mut r).map_err(|_|Error::Malformed)?;
    r.finished().map_err(|_|Error::Malformed)?;
    if e.encode()!=bytes{return Err(Error::Malformed);}
    Ok(e)
}
impl Action{
    pub fn decode(bytes:&[u8])->PzResult<Self>{
        if bytes.len()>65_536{return Err(Error::Limit);}
        let mut r=Wire::new(bytes);
        let action=match r.u8()?{
            1=>Self::Transfer{to:r.hash()?,amount:r.u64()?},
            2=>Self::Bond{operator:r.hash()?,vrf_public:r.hash()?,
                kes_public:r.sized(2048)?.to_vec(),amount:r.u64()?,
                commission_bps:r.u16()?},
            3=>Self::Exit{id:r.hash()?},
            4=>Self::Withdraw{id:r.hash()?},
            5=>{
                let test=decode_test(r.sized(16_384)?)?;
                let reward=r.u64()?;let entry_cutoff=r.u64()?;
                let evidence_cutoff=r.u64()?;let resolution=r.u64()?;
                let min_reports=r.u8()?;
                let mode=match r.u8()?{
                    0=>EvidenceMode::ScopedAttestation,
                    1=>EvidenceMode::PaidCoreCheck,_=>return Err(Error::Malformed)
                };
                let qualifying_payer=match r.u8()?{
                    0=>None,1=>Some(r.hash()?),_=>return Err(Error::Malformed)
                };
                Self::Publish{test,reward,entry_cutoff,evidence_cutoff,
                    resolution,min_reports,qualifying_payer,mode}
            }
            6=>Self::Commit{offer:r.u64()?,hash:r.hash()?},
            7=>Self::Reveal{claim:r.u64()?,
                program:decode_program(r.sized(16_384)?)?,salt:r.hash()?},
            8=>Self::FundWork{claim:r.u64()?,provider:r.hash()?,
                payment:r.u64()?,due:r.u64()?},
            9=>Self::Report{job:r.u64()?,evidence:decode_evidence(r.sized(512)?)?},
            10=>{
                let id=r.hash()?;
                let new_owner=match r.u8()?{
                    0=>None,1=>Some(r.hash()?),_=>return Err(Error::Malformed),
                };
                Self::RotateStake{id,new_owner,new_operator:r.hash()?,
                    new_vrf:r.hash()?,new_kes:r.sized(2048)?.to_vec(),
                    commission_bps:r.u16()?}
            }
            _=>return Err(Error::FrozenEra),
        };
        r.end()?;
        if action.encode()!=bytes{return Err(Error::Malformed);}
        Ok(action)
    }
}
impl SignedEvent{
    pub fn decode(bytes:&[u8])->PzResult<Self>{
        if bytes.len()>70_000{return Err(Error::Limit);}
        let mut r=Wire::new(bytes);
        let actor=r.hash()?;let nonce=r.u64()?;
        let fee_payer=r.hash()?;let fee_nonce=r.u64()?;
        let tip=r.u64()?;
        let action=Action::decode(r.sized(65_536)?)?;
        let signature:[u8;64]=r.bytes(64)?.try_into().unwrap();
        let payer_signature=match r.u8()? {
            0=>None,
            1=>Some(r.bytes(64)?.try_into().unwrap()),
            _=>return Err(Error::Malformed)
        };
        r.end()?;
        let x=Self{actor,nonce,fee_payer,fee_nonce,tip,action,signature,payer_signature};
        if x.encoded()!=bytes{return Err(Error::Malformed);}
        Ok(x)
    }
}
impl Outcome{
    pub fn decode(bytes:&[u8])->PzResult<Self>{
        let mut r=Wire::new(bytes);
        let o=match r.u8()? {
            0=>Self::Applied(r.u64()?),
            1=>{
                let e=match r.u8()? {
                    1=>Error::Malformed,2=>Error::Unauthorized,3=>Error::BadNonce,
                    4=>Error::Funds,5=>Error::Unknown,6=>Error::Expired,
                    7=>Error::Premature,8=>Error::Duplicate,9=>Error::BadEvidence,
                    10=>Error::Limit,11=>Error::Overflow,12=>Error::InvalidBlock,
                    13=>Error::InvalidProof,14=>Error::FrozenEra,15=>Error::Unavailable,
                    _=>return Err(Error::Malformed),
                };
                Self::Charged(e)
            },
            _=>return Err(Error::Malformed),
        };
        r.end()?;
        Ok(o)
    }
}
impl Block{
    pub fn encode_wire(&self)->Vec<u8>{
        let mut v=Vec::new();
        put_u64(&mut v,self.slot);
        v.extend(self.credential);
        v.extend(self.vrf_proof);
        put_u64(&mut v,self.events.len() as u64);
        for e in &self.events{
            super::put_bytes(&mut v,&e.encoded());
        }
        put_u64(&mut v,self.results.len() as u64);
        for receipt in &self.results{super::put_bytes(&mut v,&receipt.encode());}
        match &self.archive{
            None=>v.push(0),
            Some(a)=>{
                v.push(1);put_u64(&mut v,a.historic_height);
                put_u64(&mut v,a.chunk_index as u64);
                super::put_bytes(&mut v,&a.bytes);
                put_u64(&mut v,a.path.len() as u64);
                for s in &a.path{v.extend(s);}
            }
        }
        for x in [&self.body_root,&self.state_root,&self.proof_root,&self.parent]{v.extend(x);}
        super::put_bytes(&mut v,&self.kes_signature);
        v
    }
    pub fn decode_wire(bytes:&[u8],profile:&Profile)->PzResult<Self>{
        // At most 64 bounded events, their receipts and one archive witness.
        let ceiling=profile.max_block_events.checked_mul(70_100)
           .and_then(|x|x.checked_add(100_000)).ok_or(Error::Limit)?;
        if bytes.len()>ceiling {return Err(Error::Limit);}
        let mut r=Wire::new(bytes);
        let slot=r.u64()?;let credential=r.hash()?;
        let vrf_proof=r.bytes(80)?.try_into().unwrap();
        let n=usize::try_from(r.u64()?).map_err(|_|Error::Limit)?;
        if n>profile.max_block_events{return Err(Error::Limit);}
        // Bound ALL declared signed-event bytes before traversing nested
        // sponsor Core syntax. A peer cannot force expensive program decoding
        // for a proposed body already exceeding the genesis-funded block cap.
        let mut raw_events=Vec::with_capacity(n);
        let mut total_wire=0usize;
        let max_signed=profile.max_action_bytes.checked_add(225)
            .ok_or(Error::Limit)?;
        for _ in 0..n {
            let wire=r.sized(70_000)?;
            total_wire=total_wire.checked_add(wire.len()).ok_or(Error::Limit)?;
            if total_wire>profile.max_archive_bytes || wire.len()>max_signed {
                return Err(Error::Limit);
            }
            raw_events.push(wire);
        }
        let mut events=Vec::with_capacity(n);
        for wire in raw_events{
            events.push(SignedEvent::decode(wire)?);
        }
        let count=usize::try_from(r.u64()?).map_err(|_|Error::Limit)?;
        if count!=n{return Err(Error::Malformed);}
        let mut results=Vec::new();
        for _ in 0..count {
            results.push(Outcome::decode(r.sized(16)?)?);
        }
        let archive=match r.u8()?{
            0=>None,
            1=>{
                let historic_height=r.u64()?;
                let chunk_index=u32::try_from(r.u64()?).map_err(|_|Error::Limit)?;
                let bytes=r.sized(profile.max_archive_bytes)?.to_vec();
                let paths=usize::try_from(r.u64()?).map_err(|_|Error::Limit)?;
                if paths>32{return Err(Error::Limit);}
                let mut path=Vec::new();
                for _ in 0..paths{path.push(r.hash()?);}
                Some(ArchiveResponse{historic_height,chunk_index,bytes,path})
            },
            _=>return Err(Error::Malformed)
        };
        let body_root=r.hash()?;let state_root=r.hash()?;let proof_root=r.hash()?;let parent=r.hash()?;
        let kes_signature=r.sized(8192)?.to_vec();
        r.end()?;
        let b=Self{slot,credential,vrf_proof,events,results,archive,
                   body_root,state_root,proof_root,parent,kes_signature};
        if b.encode_wire()!=bytes{return Err(Error::Malformed);}
        Ok(b)
    }
}
impl Chain{
    pub fn append_wire(&mut self,bytes:&[u8])->PzResult<()>{
        self.append(Block::decode_wire(bytes,&self.genesis.profile)?)
    }
    /// A trusted host supplies the genesis identity and wall-clock slot;
    /// network peers only supply untrusted histories/bytes.
    pub fn fresh_from_received(genesis:Genesis,expected:&Hash,now_slot:u64,
        maximum_lag:u64,candidates:&[Vec<Vec<u8>>])->PzResult<Self>{
        if genesis.id()!=*expected{return Err(Error::InvalidProof);}
        if now_slot>genesis.profile.horizon{return Err(Error::Limit);}
        let mut decoded=Vec::new();
        for candidate in candidates {
            let mut blocks=Vec::new();let mut malformed=false;
            for wire in candidate{
                match Block::decode_wire(wire,&genesis.profile){
                    Ok(b)=>blocks.push(b),
                    Err(_)=>{malformed=true;break;}
                }
            }
            if !malformed{decoded.push(blocks);}
        }
        let selected=super::consensus::select_received_at_slot(genesis, &decoded,now_slot)?;
        let last=selected.blocks.last().ok_or(Error::Unavailable)?.slot;
        if last>now_slot || now_slot-last>maximum_lag {
            return Err(Error::Unavailable);
        }
        Ok(selected)
    }
}
