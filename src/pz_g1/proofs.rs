//! PZ-G1 authenticated economic *read* dependencies, reusable v2 Patricia
//! paths, and independently selected expected-root verification.
//! Proofs are not consensus, general stateless settlement or physical truth.
use super::{Hash,Error,PzResult,put_u64,put_hash,put_bytes};
use super::economy::{State,Offer,Claim,Job,EvidenceMode};
use crate::incremental_map::{PatriciaMap,MemberProof,AbsentProof};
use crate::{Failure,Evidence};
use std::collections::BTreeMap;
fn map_failure(_:Failure)->Error{Error::InvalidProof}
fn number_key(prefix:u8,id:u64)->Vec<u8>{
    let mut out=vec![prefix];out.extend(id.to_le_bytes());out
}
pub fn key_meta()->Vec<u8>{vec![0]}
pub fn key_account(id:&Hash)->Vec<u8>{
    let mut out=vec![1];out.extend(id);out
}
pub fn key_offer(id:u64)->Vec<u8>{number_key(2,id)}
pub fn key_claim(id:u64)->Vec<u8>{number_key(3,id)}
pub fn key_job(id:u64)->Vec<u8>{number_key(4,id)}
pub fn key_stake(id:&Hash)->Vec<u8>{
    let mut out=vec![5];out.extend(id);out
}
pub fn offer_value(o:&Offer)->Vec<u8>{
    let mut out=Vec::new();
    put_hash(&mut out,&o.sponsor);
    let mut test=Vec::new();o.test.encode(&mut test);
    put_bytes(&mut out,&test);
    for v in [o.reward,o.escrow,o.terminal,o.entry_cutoff,
              o.evidence_cutoff,o.resolution]{put_u64(&mut out,v);}
    out.push(o.min_reports);
    out.push(match o.mode{EvidenceMode::ScopedAttestation=>0,EvidenceMode::PaidCoreCheck=>1});
    match o.qualifying_payer{
        None=>out.push(0),Some(id)=>{out.push(1);put_hash(&mut out,&id)}
    };
    out.push(u8::from(o.resolved));
    match o.winner{
        None=>out.push(0),Some(id)=>{out.push(1);put_u64(&mut out,id)}
    };
    match o.best_eligible {
        None=>out.push(0),Some(id)=>{out.push(1);put_u64(&mut out,id)}
    };
    out
}
pub fn claim_value(c:&Claim)->Vec<u8>{
    let mut out=Vec::new();
    put_hash(&mut out,&c.optimizer);
    put_u64(&mut out,c.offer);
    put_hash(&mut out,&c.hash);
    put_u64(&mut out,c.height);
    put_u64(&mut out,c.tx_index as u64);
    match &c.program{
        None=>out.push(0),
        Some(p)=>{out.push(1);put_bytes(&mut out,&p.encode());}
    }
    put_u64(&mut out,c.qualified_reports.len() as u64);
    for id in &c.qualified_reports {put_u64(&mut out,*id);}
    out.push(u8::from(c.eligible));out.push(u8::from(c.winner));out
}
pub fn job_value(j:&Job)->Vec<u8>{
    let mut out=Vec::new();
    put_hash(&mut out,&j.payer);put_hash(&mut out,&j.provider);
    for v in [j.claim,j.fee,j.terminal,j.due]{put_u64(&mut out,v);}
    out.push(u8::from(j.qualifying));out.push(u8::from(j.closed));
    match &j.evidence{
        None=>out.push(0),
        Some(e)=>{out.push(1);put_bytes(&mut out,&e.encode())}
    }
    out
}
impl State{
    pub fn canonical_records(&self)->Vec<(Vec<u8>,Vec<u8>)>{
        let mut out=BTreeMap::new();
        let mut meta=Vec::new();
        put_hash(&mut meta,&self.genesis);
        for n in [self.height,self.slot,self.next_id,self.burned,self.minted]{
            put_u64(&mut meta,n);
        }
        out.insert(key_meta(),meta);
        for (id,a) in &self.accounts{
            let mut x=Vec::new();
            put_u64(&mut x,a.spendable);put_u64(&mut x,a.nonce);
            out.insert(key_account(id),x);
        }
        for (id,c) in &self.stake{
            let mut x=Vec::new();c.encode(&mut x);out.insert(key_stake(id),x);
        }
        for (id,o) in &self.offers{out.insert(key_offer(*id),offer_value(o));}
        for (id,c) in &self.claims{out.insert(key_claim(*id),claim_value(c));}
        for (id,j) in &self.jobs{out.insert(key_job(*id),job_value(j));}
        out.into_iter().collect()
    }
    pub fn proof_tree(&self)->PzResult<PatriciaMap>{
        PatriciaMap::from_records(self.canonical_records()).map_err(map_failure)
    }
    pub fn proof_root(&self)->PzResult<Hash>{
        Ok(self.proof_tree()?.root())
    }
    pub fn proof_for(&self,key:&[u8])->PzResult<MemberProof>{
        self.proof_tree()?.membership(key).map_err(map_failure)
    }
    pub fn absence_for(&self,key:&[u8])->PzResult<AbsentProof>{
        self.proof_tree()?.absence(key).map_err(map_failure)
    }
    pub fn bound_job_ticket(&self,job_id:u64)->PzResult<WorkTicket>{
        let job=self.jobs.get(&job_id).ok_or(Error::Unknown)?;
        let claim=self.claims.get(&job.claim).ok_or(Error::Unknown)?;
        let expected_offer=claim.offer;
        let tree=self.proof_tree()?;
        let membership=|key:Vec<u8>|tree.membership(&key).map_err(map_failure);
        Ok(WorkTicket{
            job_id,
            meta:membership(key_meta())?,
            offer:membership(key_offer(expected_offer))?,
            claim:membership(key_claim(job.claim))?,
            job:membership(key_job(job_id))?,
            snapshot_height:self.height,
            snapshot_slot:self.slot,
            claimed_offer:expected_offer,
            claimed_claim:job.claim,
        })
    }
}

#[derive(Clone,Debug)]
pub struct WorkTicket{
    pub job_id:u64,
    pub meta:MemberProof,
    pub offer:MemberProof,
    pub claim:MemberProof,
    pub job:MemberProof,
    pub snapshot_height:u64,
    pub snapshot_slot:u64,
    pub claimed_offer:u64,
    pub claimed_claim:u64,
}
fn get_hash(slice:&[u8],offset:usize)->PzResult<Hash>{
    slice.get(offset..offset+32).ok_or(Error::Malformed)?
        .try_into().map_err(|_|Error::Malformed)
}
fn get_u64(slice:&[u8],offset:usize)->PzResult<u64>{
    Ok(u64::from_le_bytes(slice.get(offset..offset+8)
        .ok_or(Error::Malformed)?.try_into().map_err(|_|Error::Malformed)?))
}
impl WorkTicket{
    /// Worker needs an independently validated, sufficiently settled state
    /// proof root, NOT the expected root supplied by the job broker alone.
    /// Structural scope is checked here, not any physical-machine truth.
    pub fn verify_read(&self,expected:&Hash,genesis:&Hash)->PzResult<()> {
        for x in [&self.meta,&self.offer,&self.claim,&self.job]{
            x.verify(expected).map_err(map_failure)?;
        }
        if self.meta.key!=key_meta() || self.offer.key!=key_offer(self.claimed_offer) ||
           self.claim.key!=key_claim(self.claimed_claim) ||
           self.job.key!=key_job(self.job_id){return Err(Error::BadEvidence);}
        if self.meta.value.len()!=72 || get_hash(&self.meta.value,0)?!=*genesis ||
           get_u64(&self.meta.value,32)?!=self.snapshot_height ||
           get_u64(&self.meta.value,40)?!=self.snapshot_slot {
            return Err(Error::BadEvidence);
        }
        if self.claim.value.len()<89 || 
           get_u64(&self.claim.value,32)?!=self.claimed_offer ||
           self.job.value.len()<99 ||
           get_u64(&self.job.value,64)?!=self.claimed_claim {
            return Err(Error::BadEvidence);
        }
        // Due is after the job's two 32-byte payer/provider fields and
        // claim,fee,terminal offsets.
        if get_u64(&self.job.value,88)?<self.snapshot_slot {
            return Err(Error::Expired);
        }
        // Bound work must remain open. Note the qualifying flag at offset96
        // and the terminal status at 97 in canonical job value layout.
        if self.job.value[97]!=0 {
            return Err(Error::Expired);
        }
        Ok(())
    }
}

const TICKET_TAG:&[u8]=b"AlgoX/PZ-G1/work-ticket/v1\0";
fn write_member(out:&mut Vec<u8>,proof:&MemberProof){
    put_u64(out,proof.count);
    put_bytes(out,&proof.key);
    put_bytes(out,&proof.value);
    put_u64(out,proof.path.len() as u64);
    for step in &proof.path{
        out.extend(step.bit.to_le_bytes());
        put_hash(out,&step.sibling);
    }
}
fn read_member(r:&mut crate::Reader<'_>)->PzResult<MemberProof>{
    let count=r.u64().map_err(|_|Error::Malformed)?;
    let key_size=usize::try_from(r.u64().map_err(|_|Error::Malformed)?)
        .map_err(|_|Error::Limit)?;
    if key_size==0 || key_size>33{return Err(Error::Limit);}
    let key=r.take(key_size).map_err(|_|Error::Malformed)?.to_vec();
    let value_size=usize::try_from(r.u64().map_err(|_|Error::Malformed)?)
        .map_err(|_|Error::Limit)?;
    if value_size>32_768{return Err(Error::Limit);}
    let value=r.take(value_size).map_err(|_|Error::Malformed)?.to_vec();
    let n=usize::try_from(r.u64().map_err(|_|Error::Malformed)?)
        .map_err(|_|Error::Limit)?;
    if n>256{return Err(Error::Limit);}
    let mut path=Vec::new();
    for _ in 0..n{
        path.push(crate::incremental_map::PathStep{
            bit:r.u16().map_err(|_|Error::Malformed)?,
            sibling:r.address().map_err(|_|Error::Malformed)?
        });
    }
    Ok(MemberProof{count,key,value,path})
}
impl WorkTicket {
    pub fn encode_wire(&self)->Vec<u8>{
        let mut out=TICKET_TAG.to_vec();
        for x in [self.job_id,self.snapshot_height,self.snapshot_slot,
                  self.claimed_offer,self.claimed_claim]{put_u64(&mut out,x);}
        for m in [&self.meta,&self.offer,&self.claim,&self.job]{
            write_member(&mut out,m);
        }
        out
    }
    pub fn decode_wire(data:&[u8])->PzResult<Self>{
        if data.len()>100_000{return Err(Error::Limit);}
        let mut r=crate::Reader::new(data);
        if r.take(TICKET_TAG.len()).map_err(|_|Error::Malformed)?!=TICKET_TAG{
            return Err(Error::Malformed);
        }
        let mut values=[0u64;5];
        for v in &mut values{*v=r.u64().map_err(|_|Error::Malformed)?;}
        let meta=read_member(&mut r)?;
        let offer=read_member(&mut r)?;
        let claim=read_member(&mut r)?;
        let job=read_member(&mut r)?;
        r.finished().map_err(|_|Error::Malformed)?;
        let ticket=Self{job_id:values[0],snapshot_height:values[1],
            snapshot_slot:values[2],claimed_offer:values[3],
            claimed_claim:values[4],meta,offer,claim,job};
        if ticket.encode_wire()!=data{return Err(Error::Malformed);}
        Ok(ticket)
    }
    /// Checks all four authenticated read dependencies before executing
    /// exactly the original sponsor's admitted deterministic Core test.
    /// Worker does not acquire independent authority to pay a bounty.
    pub fn verify_and_execute(&self,expected_root:&Hash,
        original_genesis:&Hash,budget:u64)->PzResult<Evidence>{
        self.verify_read(expected_root,original_genesis)?;
        let mut offer=crate::Reader::new(&self.offer.value);
        offer.address().map_err(|_|Error::Malformed)?; // sponsor
        let test_len=usize::try_from(offer.u64().map_err(|_|Error::Malformed)?)
            .map_err(|_|Error::Limit)?;
        if test_len>16_384{return Err(Error::Limit);}
        let test=super::codec::decode_test(
            offer.take(test_len).map_err(|_|Error::Malformed)?)?;
        let mut claim=crate::Reader::new(&self.claim.value);
        claim.take(88).map_err(|_|Error::Malformed)?;
        if claim.byte().map_err(|_|Error::Malformed)?!=1{
            return Err(Error::Premature);
        }
        let program_len=usize::try_from(claim.u64().map_err(|_|Error::Malformed)?)
            .map_err(|_|Error::Limit)?;
        if program_len>16_384{return Err(Error::Limit);}
        let candidate=super::codec::decode_program(
            claim.take(program_len).map_err(|_|Error::Malformed)?)?;
        test.evaluate(&candidate,budget).map_err(|_|Error::BadEvidence)
    }
}
