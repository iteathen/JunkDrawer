//! PZ-G1 branch-local economic transition engine: native money, stake,
//! immutable offers, signed funded work and automatic bounded due processing.
//! Deliberately separate from the old BFT fixture's Ledger::height semantics.
use super::{Hash,Owner,Profile,Genesis,Credential,Error,PzResult,BPS,digest,put_hash,put_u64,put_bytes};
use crate::{BoundTest,Program,Evidence,commitment};
use ed25519_dalek::{SigningKey,Signature,Signer,VerifyingKey};
use std::collections::{BTreeMap,BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidenceMode { ScopedAttestation, PaidCoreCheck }
impl EvidenceMode { fn tag(self)->u8 {match self{Self::ScopedAttestation=>0,Self::PaidCoreCheck=>1}} }

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Transfer {to:Owner,amount:u64},
    Bond {operator:Owner,vrf_public:Hash,kes_public:Vec<u8>,amount:u64,commission_bps:u16},
    Exit {id:Hash}, Withdraw {id:Hash},
    // One owner-signed atomic transition for operator/key/beneficial owner
    // changes. Historic e-2 snapshots preserve the preceding credential.
    RotateStake {id:Hash,new_owner:Option<Owner>,new_operator:Owner,
                 new_vrf:Hash,new_kes:Vec<u8>,commission_bps:u16},
    Publish {test:BoundTest,reward:u64,entry_cutoff:u64,evidence_cutoff:u64,
             resolution:u64,min_reports:u8,qualifying_payer:Option<Owner>,mode:EvidenceMode},
    Commit {offer:u64,hash:Hash},
    Reveal {claim:u64,program:Program,salt:Hash},
    FundWork {claim:u64,provider:Owner,payment:u64,due:u64},
    Report {job:u64,evidence:Evidence},
}
impl Action {
    pub fn encode(&self)->Vec<u8>{
        let mut o=Vec::new();
        match self {
            Self::Transfer{to,amount}=>{o.push(1);put_hash(&mut o,to);put_u64(&mut o,*amount);}
            Self::Bond{operator,vrf_public,kes_public,amount,commission_bps}=>{
                o.push(2);put_hash(&mut o,operator);put_hash(&mut o,vrf_public);
                put_bytes(&mut o,kes_public);put_u64(&mut o,*amount);
                o.extend(commission_bps.to_le_bytes());
            }
            Self::Exit{id}=>{o.push(3);put_hash(&mut o,id);}
            Self::Withdraw{id}=>{o.push(4);put_hash(&mut o,id);}
            Self::RotateStake{id,new_owner,new_operator,new_vrf,new_kes,commission_bps}=>{
                o.push(10);put_hash(&mut o,id);
                match new_owner{
                    Some(owner)=>{o.push(1);put_hash(&mut o,owner)},
                    None=>o.push(0),
                }
                put_hash(&mut o,new_operator);put_hash(&mut o,new_vrf);
                put_bytes(&mut o,new_kes);o.extend(commission_bps.to_le_bytes());
            }
            Self::Publish{test,reward,entry_cutoff,evidence_cutoff,resolution,
                          min_reports,qualifying_payer,mode}=>{
                o.push(5);
                let mut b=Vec::new();test.encode(&mut b);put_bytes(&mut o,&b);
                for x in [reward,entry_cutoff,evidence_cutoff,resolution]{put_u64(&mut o,*x);}
                o.push(*min_reports);o.push(mode.tag());
                if let Some(p)=qualifying_payer {o.push(1);put_hash(&mut o,p)}else{o.push(0);}
            }
            Self::Commit{offer,hash}=>{o.push(6);put_u64(&mut o,*offer);put_hash(&mut o,hash);}
            Self::Reveal{claim,program,salt}=>{
                o.push(7);put_u64(&mut o,*claim);put_bytes(&mut o,&program.encode());put_hash(&mut o,salt);
            }
            Self::FundWork{claim,provider,payment,due}=>{
                o.push(8);put_u64(&mut o,*claim);put_hash(&mut o,provider);
                put_u64(&mut o,*payment);put_u64(&mut o,*due);
            }
            Self::Report{job,evidence}=>{
                o.push(9);put_u64(&mut o,*job);put_bytes(&mut o,&evidence.encode());
            }
        }
        o
    }
    pub fn terminal_units(&self)->u64{
        match self {
            Self::Publish{min_reports,..}=>2+(*min_reports as u64),
            Self::FundWork{..}=>1,
            _=>0,
        }
    }
    fn state_bytes(&self)->u64{
        match self {
            Self::Publish{test,..}=>{let mut b=Vec::new();test.encode(&mut b);512+b.len() as u64}
            Self::Reveal{program,..}=>128+program.encode().len() as u64,
            Self::Bond{kes_public,..}=>160+kes_public.len() as u64,
            Self::RotateStake{new_kes,..}=>160+new_kes.len() as u64,
            Self::FundWork{..}=>256,
            Self::Report{..}=>128,
            _=>96,
        }
    }
}

#[derive(Clone, Debug)]
pub struct SignedEvent {
    pub actor:Owner,pub nonce:u64,pub fee_payer:Owner,pub fee_nonce:u64,
    pub tip:u64,pub action:Action,pub signature:[u8;64],
    pub payer_signature:Option<[u8;64]>,
}
impl SignedEvent {
    pub fn message(&self,genesis:&Hash)->Hash {
        let action=self.action.encode();
        digest(b"AlgoX/PZ-G1/signed-event/v1", &[
            genesis,&self.actor,&self.nonce.to_le_bytes(),
            &self.fee_payer,&self.fee_nonce.to_le_bytes(),&self.tip.to_le_bytes(),&action
        ])
    }
    pub fn verify(&self,genesis:&Hash)->PzResult<()> {
        let msg=self.message(genesis);
        let key=VerifyingKey::from_bytes(&self.actor).map_err(|_|Error::Unauthorized)?;
        key.verify_strict(&msg,&Signature::from_bytes(&self.signature))
            .map_err(|_|Error::Unauthorized)?;
        if self.fee_payer != self.actor {
            let p=self.payer_signature.ok_or(Error::Unauthorized)?;
            let key=VerifyingKey::from_bytes(&self.fee_payer).map_err(|_|Error::Unauthorized)?;
            key.verify_strict(&digest(b"AlgoX/PZ-G1/payer-consent/v1",&[&msg]),
               &Signature::from_bytes(&p)).map_err(|_|Error::Unauthorized)?;
        }else if self.fee_nonce!=self.nonce || self.payer_signature.is_some() {
            return Err(Error::Malformed);
        }
        Ok(())
    }
    pub fn sign(genesis:&Hash,actor:&SigningKey,nonce:u64,tip:u64,action:Action,
                separate_payer:Option<(&SigningKey,u64)>)->Self {
        let owner=actor.verifying_key().to_bytes();
        let (payer,fee_nonce)=separate_payer.as_ref().map_or((owner,nonce),
            |(key,n)|(key.verifying_key().to_bytes(),*n));
        let mut e=Self{actor:owner,nonce,fee_payer:payer,fee_nonce,tip,action,
                       signature:[0u8;64],payer_signature:None};
        let msg=e.message(genesis);
        e.signature=actor.sign(&msg).to_bytes();
        if let Some((key,_))=separate_payer {
            e.payer_signature=Some(key.sign(&digest(b"AlgoX/PZ-G1/payer-consent/v1",
                &[&msg])).to_bytes());
        }
        e
    }
    pub fn encoded(&self)->Vec<u8>{
        let mut v=Vec::new();
        put_hash(&mut v,&self.actor);put_u64(&mut v,self.nonce);
        put_hash(&mut v,&self.fee_payer);put_u64(&mut v,self.fee_nonce);
        put_u64(&mut v,self.tip);put_bytes(&mut v,&self.action.encode());
        v.extend(self.signature);
        match self.payer_signature {Some(p)=>{v.push(1);v.extend(p);},None=>v.push(0)}
        v
    }
}

#[derive(Clone,Debug,Default,PartialEq,Eq)]
pub struct Account{pub spendable:u64,pub nonce:u64}
#[derive(Clone,Debug)]
pub struct Offer{
    pub sponsor:Owner,pub test:BoundTest,pub reward:u64,
    pub escrow:u64,pub terminal:u64,pub entry_cutoff:u64,
    pub evidence_cutoff:u64,pub resolution:u64,pub min_reports:u8,
    pub qualifying_payer:Option<Owner>,pub mode:EvidenceMode,
    pub resolved:bool,pub winner:Option<u64>,pub best_eligible:Option<u64>,
}
#[derive(Clone,Debug)]
pub struct Claim{
    pub optimizer:Owner,pub offer:u64,pub hash:Hash,
    pub height:u64,pub tx_index:u32,
    pub program:Option<Program>,
    pub qualified_reports:BTreeSet<u64>,
    pub eligible:bool,pub winner:bool,
}
#[derive(Clone,Debug)]
pub struct Job{
    pub payer:Owner,pub provider:Owner,pub claim:u64,
    pub fee:u64,pub terminal:u64,pub due:u64,
    pub qualifying:bool,pub evidence:Option<Evidence>,
    pub closed:bool,
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum Outcome{Applied(u64),Charged(Error)}
impl Outcome {
    pub fn encode(self)->Vec<u8>{
        let mut o=Vec::new();match self{
            Self::Applied(x)=>{o.push(0);put_u64(&mut o,x)},
            Self::Charged(x)=>o.extend([1,x as u8]),
        }o
    }
}

#[derive(Clone,Debug)]
pub struct State{
    pub genesis:Hash,pub accounts:BTreeMap<Owner,Account>,
    pub stake:BTreeMap<Hash,Credential>,
    pub offers:BTreeMap<u64,Offer>,pub claims:BTreeMap<u64,Claim>,
    pub jobs:BTreeMap<u64,Job>,
    // Derived, path-local maturity and offer-priority indexes. No full-state
    // sweep is needed to service one bounded due-event batch.
    pub due:BTreeSet<(u64,u8,u64)>,
    pub claims_by_offer:BTreeMap<u64,BTreeSet<(u64,u32,u64)>>,
    pub burned:u64,pub minted:u64,
    pub next_id:u64,pub height:u64,pub slot:u64,
}
impl State{
    pub fn from_genesis(genesis:&Genesis)->PzResult<Self>{
        genesis.validate()?;
        let mut accounts=BTreeMap::new();
        for (key,value) in &genesis.accounts{
            accounts.insert(*key,Account{spendable:*value,nonce:0});
        }
        let stake=genesis.locked.iter().map(|x|(x.id,x.clone())).collect();
        Ok(Self{genesis:genesis.id(),accounts,stake,offers:BTreeMap::new(),
                claims:BTreeMap::new(),jobs:BTreeMap::new(),due:BTreeSet::new(),
                claims_by_offer:BTreeMap::new(),burned:0,minted:0,
                next_id:1,height:0,slot:0})
    }
    pub fn account(&self,a:&Owner)->Account {self.accounts.get(a).cloned().unwrap_or_default()}
    pub fn balance(&self,a:&Owner)->u64 {self.account(a).spendable}
    fn debit(&mut self,a:Owner,amount:u64)->PzResult<()>{
        let mut x=self.account(&a);
        x.spendable=x.spendable.checked_sub(amount).ok_or(Error::Funds)?;
        self.accounts.insert(a,x);Ok(())
    }
    fn credit(&mut self,a:Owner,amount:u64)->PzResult<()>{
        let mut x=self.account(&a);
        x.spendable=x.spendable.checked_add(amount).ok_or(Error::Overflow)?;
        self.accounts.insert(a,x);Ok(())
    }
    fn bump(&mut self,a:Owner)->PzResult<()>{
        let mut x=self.account(&a);
        x.nonce=x.nonce.checked_add(1).ok_or(Error::Overflow)?;
        self.accounts.insert(a,x);Ok(())
    }
    fn new_id(&mut self)->PzResult<u64>{
        let x=self.next_id;self.next_id=x.checked_add(1).ok_or(Error::Overflow)?;Ok(x)
    }
    pub fn quote(&self,p:&Profile,event:&SignedEvent)->PzResult<u64>{
        let action_bytes=event.action.encode();
        if action_bytes.len()>p.max_action_bytes {return Err(Error::Limit);}
        let wire_len=event.encoded().len() as u128;
        let signed=if event.actor==event.fee_payer{1u128}else{2};
        let core=if let Action::Report{job,..}=&event.action {
            let mode=self.jobs.get(job)
                .and_then(|j|self.claims.get(&j.claim))
                .and_then(|c|self.offers.get(&c.offer))
                .map(|o|o.mode);
            if mode==Some(EvidenceMode::PaidCoreCheck){
                p.max_core_steps as u128
            }else{0}
        }else{0};
        let x=wire_len*(p.prices.per_byte as u128)+
            signed*(p.prices.per_signature as u128)+
            core*(p.prices.per_core_step as u128)+
            (event.action.state_bytes() as u128)*(p.prices.per_state_byte as u128);
        u64::try_from(x).map_err(|_|Error::Overflow)
    }
    fn terminal_fee(p:&Profile,units:u64)->PzResult<u64>{
        p.prices.per_terminal.checked_mul(units).ok_or(Error::Overflow)
    }
    /// Invalid signature, nonce and pre-payment never become a block event.
    /// Correctly signed and affordable contract failures burn the base fee
    /// and consume exactly the corresponding authorization nonces once.
    pub fn apply(&mut self,p:&Profile,event:&SignedEvent,
                 slot:u64,parent_height:u64,index:u32,operator:Owner,stable_slot:u64)->PzResult<Outcome>{
        event.verify(&self.genesis)?;
        if self.account(&event.actor).nonce!=event.nonce ||
           self.account(&event.fee_payer).nonce!=event.fee_nonce {return Err(Error::BadNonce);}
        let base=self.quote(p,event)?;
        let required=base.checked_add(event.tip).ok_or(Error::Overflow)?;
        if self.balance(&event.fee_payer)<required{return Err(Error::Funds);}
        let mut charged=self.clone();
        charged.debit(event.fee_payer,required)?;
        charged.bump(event.actor)?;
        if event.fee_payer!=event.actor {charged.bump(event.fee_payer)?;}
        charged.burned=charged.burned.checked_add(base).ok_or(Error::Overflow)?;
        charged.credit(operator,event.tip)?;
        let mut business=charged.clone();
        match business.execute(p,event.actor,&event.action,slot,parent_height,index,stable_slot) {
            Ok(value)=>{*self=business;Ok(Outcome::Applied(value))}
            Err(error)=>{*self=charged;Ok(Outcome::Charged(error))}
        }
    }
    fn execute(&mut self,p:&Profile,actor:Owner,action:&Action,
               slot:u64,parent_height:u64,index:u32,stable_slot:u64)->PzResult<u64>{
        match action{
            Action::Transfer{to,amount}=>{
                self.debit(actor,*amount)?;self.credit(*to,*amount)?;Ok(*amount)
            }
            Action::Bond{operator,vrf_public,kes_public,amount,commission_bps}=>{
                if *amount==0{return Err(Error::Malformed);}
                let cred=Credential{
                    id:Credential::make_id(&actor,vrf_public,kes_public),
                    owner:actor,operator:*operator,amount:*amount,
                    vrf_public:*vrf_public,kes_public:kes_public.clone(),
                    commission_bps:*commission_bps,exit_epoch:None,
                    exit_requested_height:None,
                };
                cred.validate()?;
                if self.stake.contains_key(&cred.id){return Err(Error::Duplicate);}
                let next=self.stake.values().map(|x|x.amount as u128).sum::<u128>()+
                    (*amount as u128);
                if next>1024{return Err(Error::Limit);}
                self.debit(actor,*amount)?;
                self.stake.insert(cred.id,cred);
                Ok(*amount)
            }
            Action::Exit{id}=>{
                let cred=self.stake.get_mut(id).ok_or(Error::Unknown)?;
                if cred.owner!=actor{return Err(Error::Unauthorized);}
                if cred.exit_epoch.is_some(){return Err(Error::Duplicate);}
                cred.exit_epoch=Some(p.epoch(slot));
                cred.exit_requested_height=Some(parent_height+1);
                Ok(0)
            }
            Action::Withdraw{id}=>{
                let cred=self.stake.get(id).ok_or(Error::Unknown)?.clone();
                if cred.owner!=actor{return Err(Error::Unauthorized);}
                let e=cred.exit_epoch.ok_or(Error::Premature)?;
                // All stake snapshots through epoch e+1 may still include it.
                // Require an already k-deep *block at or after* that epoch's end.
                let end=(e+2).checked_mul(p.epoch_slots).ok_or(Error::Overflow)?
                     .checked_sub(1).ok_or(Error::Overflow)?;
                if slot<=end || stable_slot<end || parent_height<p.k_blocks{
                    return Err(Error::Premature);
                }
                self.stake.remove(id);
                self.credit(actor,cred.amount)?;
                Ok(cred.amount)
            }
            Action::RotateStake{id,new_owner,new_operator,new_vrf,new_kes,commission_bps}=>{
                let old=self.stake.get(id).ok_or(Error::Unknown)?.clone();
                if old.owner!=actor{return Err(Error::Unauthorized);}
                if old.exit_epoch.is_some(){return Err(Error::Expired);}
                let owner=new_owner.unwrap_or(old.owner);
                let mut updated=old.clone();
                updated.owner=owner;updated.operator=*new_operator;
                updated.vrf_public=*new_vrf;updated.kes_public=new_kes.clone();
                updated.commission_bps=*commission_bps;
                updated.id=Credential::make_id(&owner,new_vrf,new_kes);
                updated.validate()?;
                if updated.id!=old.id && self.stake.contains_key(&updated.id){
                    return Err(Error::Duplicate);
                }
                self.stake.remove(id);
                self.stake.insert(updated.id,updated);
                Ok(old.amount)
            }
            Action::Publish{test,reward,entry_cutoff,evidence_cutoff,resolution,
                            min_reports,qualifying_payer,mode}=>{
                test.validate().map_err(|_|Error::Malformed)?;
                if *entry_cutoff<slot || *evidence_cutoff<=*entry_cutoff ||
                   *resolution<=*evidence_cutoff || *resolution>p.horizon ||
                   *min_reports>64 ||
                   (*mode==EvidenceMode::PaidCoreCheck && *min_reports==0) {
                    // A paid deterministic test must be an actual condition
                    // of award. Zero required reports would otherwise pay an
                    // unchecked candidate while advertising Core verification.
                    return Err(Error::Malformed);
                }
                let terminal=Self::terminal_fee(p,action.terminal_units())?;
                let total=reward.checked_add(terminal).ok_or(Error::Overflow)?;
                let already=self.due.range((*resolution,0,0)..=(*resolution,1,u64::MAX)).count();
                if already>=p.max_due_per_block{return Err(Error::Limit);}
                self.debit(actor,total)?;
                let id=self.new_id()?;
                self.offers.insert(id,Offer{sponsor:actor,test:test.clone(),
                    reward:*reward,escrow:*reward,terminal,
                    entry_cutoff:*entry_cutoff,evidence_cutoff:*evidence_cutoff,
                    resolution:*resolution,min_reports:*min_reports,
                    qualifying_payer:*qualifying_payer,mode:*mode,
                    resolved:false,winner:None,best_eligible:None});
                self.due.insert((*resolution,1,id));
                Ok(id)
            }
            Action::Commit{offer,hash}=>{
                let o=self.offers.get(offer).ok_or(Error::Unknown)?;
                if o.resolved || slot>o.entry_cutoff{return Err(Error::Expired);}
                let id=self.new_id()?;
                self.claims.insert(id,Claim{optimizer:actor,offer:*offer,hash:*hash,
                    height:parent_height+1,tx_index:index,program:None,
                    qualified_reports:BTreeSet::new(),eligible:false,winner:false});
                self.claims_by_offer.entry(*offer).or_default().insert((parent_height+1,index,id));
                Ok(id)
            }
            Action::Reveal{claim,program,salt}=>{
                program.validate().map_err(|_|Error::Malformed)?;
                let c=self.claims.get(claim).ok_or(Error::Unknown)?.clone();
                let o=self.offers.get(&c.offer).ok_or(Error::Unknown)?;
                if c.optimizer!=actor{return Err(Error::Unauthorized);}
                if c.program.is_some(){return Err(Error::Duplicate);}
                if slot>o.evidence_cutoff{return Err(Error::Expired);}
                if parent_height.saturating_sub(c.height)<p.k_blocks{return Err(Error::Premature);}
                if commitment(program,salt)!=c.hash{return Err(Error::BadEvidence);}
                if program.arity!=o.test.arity(){return Err(Error::Malformed);}
                let original_minimum=o.min_reports;
                self.claims.get_mut(claim).ok_or(Error::Unknown)?.program=Some(program.clone());
                if original_minimum==0 {
                    self.record_eligible_claim(*claim)?;
                }
                Ok(*claim)
            }
            Action::FundWork{claim,provider,payment,due}=>{
                let c=self.claims.get(claim).ok_or(Error::Unknown)?;
                if c.program.is_none(){return Err(Error::Premature);}
                let o=self.offers.get(&c.offer).ok_or(Error::Unknown)?;
                if *due<slot || *due>p.horizon{return Err(Error::Malformed);}
                if self.due.range((*due,0,0)..=(*due,1,u64::MAX)).count()>=p.max_due_per_block {
                    return Err(Error::Limit);
                }
                let qualifying=!o.resolved && slot<=o.evidence_cutoff &&
                    *due<=o.evidence_cutoff &&
                    o.qualifying_payer.is_none_or(|x|x==actor);
                let terminal=Self::terminal_fee(p,action.terminal_units())?;
                self.debit(actor,payment.checked_add(terminal).ok_or(Error::Overflow)?)?;
                let id=self.new_id()?;
                self.jobs.insert(id,Job{payer:actor,provider:*provider,claim:*claim,fee:*payment,
                    terminal,due:*due,qualifying,evidence:None,closed:false});
                self.due.insert((*due,0,id));
                Ok(id)
            }
            Action::Report{job,evidence}=>{
                let j=self.jobs.get(job).ok_or(Error::Unknown)?.clone();
                if j.closed || j.evidence.is_some(){return Err(Error::Duplicate);}
                if j.provider!=actor{return Err(Error::Unauthorized);}
                if slot>j.due{return Err(Error::Expired);}
                let claim=self.claims.get(&j.claim).ok_or(Error::Unknown)?.clone();
                let offer=self.offers.get(&claim.offer).ok_or(Error::Unknown)?.clone();
                if offer.mode==EvidenceMode::PaidCoreCheck {
                    let program=claim.program.as_ref().ok_or(Error::Premature)?;
                    let measured=offer.test.evaluate(program,p.max_core_steps)
                        .map_err(|_|Error::BadEvidence)?;
                    if measured!=*evidence{return Err(Error::BadEvidence);}
                }
                let x=self.jobs.get_mut(job).ok_or(Error::Unknown)?;
                x.evidence=Some(evidence.clone());x.closed=true;x.fee=0;x.terminal=0;
                self.credit(actor,j.fee)?;
                self.burned=self.burned.checked_add(j.terminal).ok_or(Error::Overflow)?;
                self.due.remove(&(j.due,0,*job));
                if j.qualifying && evidence.accepted && slot<=offer.evidence_cutoff {
                    let count={
                        let target=self.claims.get_mut(&j.claim)
                            .ok_or(Error::Unknown)?;
                        target.qualified_reports.insert(*job);
                        target.qualified_reports.len()
                    };
                    if count>=offer.min_reports as usize {
                        self.record_eligible_claim(j.claim)?;
                    }
                }
                Ok(*job)
            }
        }
    }
    /// Eligibility is maintained when new valid evidence arrives, not by
    /// scanning potentially unbounded candidate registrations at expiry.
    /// Ordered commit priority is stable even if later commitments qualify
    /// sooner than earlier commitments.
    fn record_eligible_claim(&mut self,claim_id:u64)->PzResult<()>{
        let claim=self.claims.get(&claim_id).ok_or(Error::Unknown)?.clone();
        let offer=self.offers.get(&claim.offer).ok_or(Error::Unknown)?;
        if offer.resolved || claim.program.is_none() ||
           claim.qualified_reports.len()<offer.min_reports as usize {
            return Err(Error::Premature);
        }
        let candidate_key=(claim.height,claim.tx_index,claim_id);
        let better=match offer.best_eligible {
            None=>true,
            Some(prior)=>{
                let c=self.claims.get(&prior).ok_or(Error::InvalidBlock)?;
                candidate_key < (c.height,c.tx_index,prior)
            }
        };
        self.claims.get_mut(&claim_id).ok_or(Error::InvalidBlock)?.eligible=true;
        if better {
            self.offers.get_mut(&claim.offer)
                .ok_or(Error::InvalidBlock)?.best_eligible=Some(claim_id);
        }
        Ok(())
    }
    /// Path-local, oldest-first bounded discharge with fixed due keys. No
    /// unbounded scan; all reserves were authenticated at original admission.
    pub fn process_due(&mut self,_p:&Profile,slot:u64,limit:usize)->PzResult<usize>{
        let ready:Vec<(u64,u8,u64)>=self.due.iter()
            .take_while(|(due,_,_)|*due<=slot)
            .take(limit)
            .copied().collect();
        for &(due,kind,id) in &ready {
            if kind==0 {
                let job=self.jobs.get(&id).ok_or(Error::Unknown)?.clone();
                if job.closed || job.due!=due{return Err(Error::InvalidBlock);}
                self.credit(job.payer,job.fee)?;
                self.burned=self.burned.checked_add(job.terminal).ok_or(Error::Overflow)?;
                let j=self.jobs.get_mut(&id).ok_or(Error::Unknown)?;
                j.fee=0;j.terminal=0;j.closed=true;
            } else {
                let offer=self.offers.get(&id).ok_or(Error::Unknown)?.clone();
                if offer.resolved || offer.resolution!=due{return Err(Error::InvalidBlock);}
                // All claims earned and retained qualification when their
                // original evidence arrived. Maturity is O(1) in the number
                // of registered claims; the sponsor's terminal reserve does
                // not secretly pay for scanning unbounded candidate lists.
                let winning=offer.best_eligible;
                if let Some(w)=winning{
                    let beneficiary=self.claims.get(&w).ok_or(Error::InvalidBlock)?.optimizer;
                    self.credit(beneficiary,offer.escrow)?;
                    self.claims.get_mut(&w).ok_or(Error::InvalidBlock)?.winner=true;
                }else{self.credit(offer.sponsor,offer.escrow)?;}
                self.burned=self.burned.checked_add(offer.terminal).ok_or(Error::Overflow)?;
                let x=self.offers.get_mut(&id).ok_or(Error::Unknown)?;
                x.resolved=true;x.winner=winning;x.escrow=0;x.terminal=0;
            }
            if !self.due.remove(&(due,kind,id)){return Err(Error::InvalidBlock);}
        }
        Ok(ready.len())
    }
    /// The indexes are derived acceleration structures. They affect future
    /// payouts and therefore must never be trusted merely because a supplied
    /// checkpoint has a matching account/rights root. Full replay constructs
    /// them deterministically, but externally imported checkpoint state must
    /// separately demonstrate consistency with the committed primary records.
    pub fn validate_indexes(&self)->PzResult<()> {
        let mut due=BTreeSet::new();
        for (id,offer) in &self.offers{
            if !offer.resolved{due.insert((offer.resolution,1,*id));}
        }
        for (id,job) in &self.jobs{
            if !job.closed{due.insert((job.due,0,*id));}
        }
        if due!=self.due{return Err(Error::InvalidProof);}
        let mut claims:BTreeMap<u64,BTreeSet<(u64,u32,u64)>>=BTreeMap::new();
        for (id,claim) in &self.claims {
            if !self.offers.contains_key(&claim.offer){return Err(Error::InvalidProof);}
            claims.entry(claim.offer).or_default().insert((
                claim.height,claim.tx_index,*id));
        }
        if claims!=self.claims_by_offer{return Err(Error::InvalidProof);}
        for (offer_id,offer) in &self.offers {
            let first=claims.get(offer_id).and_then(|ordered|{
                ordered.iter().find_map(|(_,_,claim_id)|{
                    let claim=self.claims.get(claim_id)?;
                    if claim.eligible{Some(*claim_id)}else{None}
                })
            });
            if offer.best_eligible!=first ||
               (offer.resolved && offer.winner!=first) {
                return Err(Error::InvalidProof);
            }
        }
        for claim in self.claims.values() {
            let offer=self.offers.get(&claim.offer).ok_or(Error::InvalidProof)?;
            if claim.eligible && (claim.program.is_none() ||
                claim.qualified_reports.len()<offer.min_reports as usize) {
                return Err(Error::InvalidProof);
            }
        }
        for job in self.jobs.values(){
            if !self.claims.contains_key(&job.claim){return Err(Error::InvalidProof);}
        }
        Ok(())
    }
    pub fn due_backlog(&self,slot:u64)->bool{
        self.due.iter().next().is_some_and(|(due,_,_)|*due<slot)
    }
    pub fn due_ready(&self,slot:u64)->usize{
        self.due.iter().take_while(|(due,_,_)|*due<=slot).count()
    }
    pub fn issue(&mut self,base:u64,data:u64,owner:Owner,operator:Owner,
                 commission_bps:u16)->PzResult<()> {
        let reward=base.checked_add(data).ok_or(Error::Overflow)?;
        let operator_part=(reward as u128)*(commission_bps as u128)/(BPS as u128);
        let op=u64::try_from(operator_part).map_err(|_|Error::Overflow)?;
        self.credit(owner,reward-op)?;
        self.credit(operator,op)?;
        self.minted=self.minted.checked_add(reward).ok_or(Error::Overflow)?;
        Ok(())
    }
    pub fn value_total(&self)->u128{
        self.accounts.values().map(|x|x.spendable as u128).sum::<u128>()+
        self.stake.values().map(|x|x.amount as u128).sum::<u128>()+
        self.offers.values().map(|x|(x.escrow as u128)+(x.terminal as u128)).sum::<u128>()+
        self.jobs.values().map(|x|(x.fee as u128)+(x.terminal as u128)).sum::<u128>()
    }
    pub fn assert_supply(&self,genesis:&Genesis)->PzResult<()>{
        let origin=genesis.initial_supply()? as u128;
        let expected=origin.checked_add(self.minted as u128).ok_or(Error::Overflow)?
           .checked_sub(self.burned as u128).ok_or(Error::Overflow)?;
        if self.value_total()!=expected {return Err(Error::InvalidBlock);}
        Ok(())
    }
    pub fn root(&self)->Hash{
        let mut o=Vec::new();
        put_hash(&mut o,&self.genesis);
        for n in [self.height,self.slot,self.next_id,self.burned,self.minted]{put_u64(&mut o,n);}
        put_u64(&mut o,self.accounts.len() as u64);
        for (k,a) in &self.accounts{
            put_hash(&mut o,k);put_u64(&mut o,a.spendable);put_u64(&mut o,a.nonce);
        }
        put_u64(&mut o,self.stake.len() as u64);
        for c in self.stake.values(){c.encode(&mut o);}
        put_u64(&mut o,self.offers.len() as u64);
        for (id,offer) in &self.offers {
            put_u64(&mut o,*id);put_hash(&mut o,&offer.sponsor);
            let mut t=Vec::new();offer.test.encode(&mut t);put_bytes(&mut o,&t);
            for x in [offer.reward,offer.escrow,offer.terminal,
                      offer.entry_cutoff,offer.evidence_cutoff,offer.resolution]{put_u64(&mut o,x);}
            o.push(offer.min_reports);o.push(offer.mode.tag());
            match offer.qualifying_payer{Some(p)=>{o.push(1);put_hash(&mut o,&p)},None=>o.push(0)}
            o.push(offer.resolved as u8);
            match offer.winner {Some(x)=>{o.push(1);put_u64(&mut o,x)},None=>o.push(0)}
            match offer.best_eligible {Some(x)=>{o.push(1);put_u64(&mut o,x)},None=>o.push(0)}
        }
        put_u64(&mut o,self.claims.len() as u64);
        for (id,c) in &self.claims{
            put_u64(&mut o,*id);put_hash(&mut o,&c.optimizer);
            put_u64(&mut o,c.offer);put_hash(&mut o,&c.hash);
            put_u64(&mut o,c.height);put_u64(&mut o,c.tx_index as u64);
            match &c.program{Some(p)=>{o.push(1);put_bytes(&mut o,&p.encode())},None=>o.push(0)}
            put_u64(&mut o,c.qualified_reports.len() as u64);
            for j in &c.qualified_reports{put_u64(&mut o,*j);}
            o.push(c.eligible as u8);o.push(c.winner as u8);
        }
        put_u64(&mut o,self.jobs.len() as u64);
        for (id,j) in &self.jobs{
            put_u64(&mut o,*id);put_hash(&mut o,&j.payer);put_hash(&mut o,&j.provider);
            for x in [j.claim,j.fee,j.terminal,j.due]{put_u64(&mut o,x);}
            o.push(j.qualifying as u8);o.push(j.closed as u8);
            match &j.evidence{Some(e)=>{o.push(1);put_bytes(&mut o,&e.encode())},None=>o.push(0)}
        }
        digest(b"AlgoX/PZ-G1/economic-root/v1",&[&o])
    }
}
