//! Experiment 018 area 1: sponsor-declared reference outputs and abstract
//! costs using the EXISTING Core executor. No new execution engine or
//! mandatory baseline replay. The sponsor, not AlgoX, owns reference meaning.
//! This is a versioned Phase Zero optional test shape, not yet an accepted
//! posted-bounty encoding (the old Problem ABI is unchanged).

use super::{Program,Reader,Meter,eval,Evidence,Failure,Result};
use sha2::{Digest,Sha256};

const TAG:&[u8]=b"AlgoX-PhaseZero/sponsor-references/v1\0";
const MAX_CASES:usize=64;
#[derive(Clone,Debug,PartialEq,Eq)]
pub struct ReferenceCase{
    pub args:Vec<i64>,
    pub expected_output:i64,
    pub reference_cost:u64,
}
#[derive(Clone,Debug,PartialEq,Eq)]
pub struct SponsorReferences{
    pub arity:u8,
    pub cases:Vec<ReferenceCase>,
    pub costs:[u64;8],
    pub min_saving:u64,
}
impl SponsorReferences{
    pub fn validate(&self)->Result<()>{
        if self.arity>8 || self.cases.is_empty() ||
           self.cases.len()>MAX_CASES ||
           self.cases.iter().any(|c|c.args.len()!=self.arity as usize){
            return Err(Failure::Malformed);
        }
        let mut total=0u64;
        for row in &self.cases{
            total=total.checked_add(row.reference_cost).ok_or(Failure::Overflow)?;
        }
        Ok(())
    }
    // Admitted contracts validate before using this deterministic encoder.
    pub fn raw_encode(&self)->Vec<u8>{
        let mut out=TAG.to_vec();
        out.push(self.arity);
        out.push(self.cases.len() as u8);
        for item in &self.cases{
            for &arg in &item.args{out.extend(arg.to_le_bytes());}
            out.extend(item.expected_output.to_le_bytes());
            out.extend(item.reference_cost.to_le_bytes());
        }
        for &cost in &self.costs{out.extend(cost.to_le_bytes());}
        out.extend(self.min_saving.to_le_bytes());
        out
    }
    pub fn encode(&self)->Result<Vec<u8>>{
        self.validate()?;Ok(self.raw_encode())
    }
    pub fn decode(data:&[u8])->Result<Self>{
        let mut r=Reader::new(data);
        if r.take(TAG.len())?!=TAG{return Err(Failure::Unsupported);}
        let arity=r.byte()?;
        let count=r.byte()? as usize;
        if arity>8 || count==0 || count>MAX_CASES{
            return Err(Failure::Malformed);
        }
        let mut cases=Vec::with_capacity(count);
        for _ in 0..count{
            let mut args=Vec::with_capacity(arity as usize);
            for _ in 0..arity {args.push(r.i64()?);}
            cases.push(ReferenceCase{
                args,
                expected_output:r.i64()?,
                reference_cost:r.u64()?
            });
        }
        let mut costs=[0u64;8];
        for cost in &mut costs{*cost=r.u64()?;}
        let out=Self{arity,cases,costs,min_saving:r.u64()?};
        r.finished()?;
        out.validate()?;
        Ok(out)
    }
    /// Only the admitted candidate executes; sponsor-declared reference
    /// numbers are contract data, never network-certified physical facts.
    pub fn evaluate(&self,candidate:&Program,step_budget:u64)->Result<Evidence>{
        self.validate()?;
        candidate.validate()?;
        if candidate.arity!=self.arity || step_budget==0 ||
           step_budget>1_000_000{return Err(Failure::Malformed);}
        let mut meter=Meter{costs:&self.costs,steps:0,limit:step_budget,cost:0};
        let mut reference_total=0u64;
        let mut candidate_total=0u64;
        let mut all_equal=true;
        let mut digest=Sha256::new();
        digest.update(TAG);
        for row in &self.cases {
            reference_total=reference_total.checked_add(row.reference_cost)
                .ok_or(Failure::Overflow)?;
            let cost_before=meter.cost;
            let result=eval(&candidate.body,candidate,&row.args,&mut meter,0);
            let value=match result{
                Ok(v)=>v,
                Err(Failure::ArithmeticTrap)=>{all_equal=false;i64::MIN},
                Err(other)=>return Err(other),
            };
            let cost=meter.cost-cost_before;
            candidate_total=candidate_total.checked_add(cost)
                .ok_or(Failure::Overflow)?;
            if value!=row.expected_output{all_equal=false;}
            for &arg in &row.args{digest.update(arg.to_le_bytes());}
            digest.update(row.expected_output.to_le_bytes());
            digest.update(value.to_le_bytes());
            digest.update(row.reference_cost.to_le_bytes());
            digest.update(cost.to_le_bytes());
        }
        let accepted=all_equal && reference_total>=candidate_total &&
            reference_total-candidate_total>=self.min_saving;
        Ok(Evidence{accepted,baseline_cost:reference_total,
            candidate_cost:candidate_total,transcript:digest.finalize().into()})
    }
}
