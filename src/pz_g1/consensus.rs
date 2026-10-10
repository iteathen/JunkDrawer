//! PZ-G1 cryptographic slot chain, full economic validation, sampled historic
//! chunks, branch rollback and conditional long-history choice.
//! Network delivery, honest stake and full proof correspondence are NOT
//! produced by this deterministic research engine.
use super::{Hash,Owner,Genesis,Profile,Credential,Error,PzResult,digest,put_hash,put_u64,put_bytes,wins};
use super::economy::{State,SignedEvent,Outcome};
use cardano_crypto::vrf::VrfDraft03;
use cardano_crypto::kes::{Sum7Kes,KesAlgorithm};
use std::cmp::Ordering;
const CHUNK:usize=512;

fn leaf(index:usize,bytes:&[u8])->Hash{
    digest(b"AlgoX/PZ-G1/chunk-leaf/v1",&[&(index as u64).to_le_bytes(),bytes])
}
fn pair(a:&Hash,b:&Hash)->Hash{
    digest(b"AlgoX/PZ-G1/chunk-node/v1",&[a,b])
}
fn merkle_root(data:&[u8])->Hash{
    let mut level:Vec<Hash>=data.chunks(CHUNK).enumerate()
        .map(|(i,c)|leaf(i,c)).collect();
    if level.is_empty(){level.push(leaf(0,&[]));}
    while level.len()>1 {
        let mut next=Vec::new();
        for chunk in level.chunks(2) {
            next.push(pair(&chunk[0],chunk.get(1).unwrap_or(&chunk[0])));
        }
        level=next;
    }
    level[0]
}
fn proof(data:&[u8],index:usize)->PzResult<(Vec<u8>,Vec<Hash>)>{
    let chunks:Vec<&[u8]>=data.chunks(CHUNK).collect();
    if index>=chunks.len(){return Err(Error::InvalidProof);}
    let mut i=index;
    let mut level:Vec<Hash>=chunks.iter().enumerate().map(|(j,c)|leaf(j,c)).collect();
    let mut path=Vec::new();
    while level.len()>1 {
        path.push(*level.get(i^1).unwrap_or(&level[i]));
        i/=2;
        let mut next=Vec::new();
        for pair_items in level.chunks(2) {
            next.push(pair(&pair_items[0],pair_items.get(1).unwrap_or(&pair_items[0])));
        }
        level=next;
    }
    Ok((chunks[index].to_vec(),path))
}
pub fn verify_chunk(root:&Hash,total_bytes:usize,index:usize,bytes:&[u8],path:&[Hash])->PzResult<()>{
    if total_bytes==0 || index>=total_bytes.div_ceil(CHUNK) ||
       bytes.len()!= (total_bytes-index*CHUNK).min(CHUNK) ||
       path.len()>32 {return Err(Error::InvalidProof);}
    let mut size=total_bytes.div_ceil(CHUNK);
    let mut i=index;
    let mut h=leaf(index,bytes);
    for other in path {
        if size<=1{return Err(Error::InvalidProof);}
        if i%2==0 {h=pair(&h,other)}else{h=pair(other,&h)}
        i/=2;size=size.div_ceil(2);
    }
    if size!=1 || &h!=root {return Err(Error::InvalidProof);}
    Ok(())
}

#[derive(Clone,Debug)]
pub struct ArchiveResponse{
    pub historic_height:u64,pub chunk_index:u32,
    pub bytes:Vec<u8>,pub path:Vec<Hash>,
}
impl ArchiveResponse{
    fn encode(&self,o:&mut Vec<u8>){
        put_u64(o,self.historic_height);put_u64(o,self.chunk_index as u64);
        put_bytes(o,&self.bytes);put_u64(o,self.path.len() as u64);
        for x in &self.path{put_hash(o,x);}
    }
}
#[derive(Clone,Debug)]
pub struct Block{
    pub slot:u64,pub credential:Hash,pub vrf_proof:[u8;80],
    pub events:Vec<SignedEvent>,pub results:Vec<Outcome>,
    pub archive:Option<ArchiveResponse>,
    pub body_root:Hash,pub state_root:Hash,
    pub proof_root:Hash,pub parent:Hash,
    pub kes_signature:Vec<u8>,
}
impl Block{
    fn body_bytes(&self)->Vec<u8>{
        let mut o=Vec::new();put_u64(&mut o,self.slot);
        put_hash(&mut o,&self.credential);
        put_u64(&mut o,self.events.len() as u64);
        for (ev,result) in self.events.iter().zip(&self.results) {
            put_bytes(&mut o,&ev.encoded());
            put_bytes(&mut o,&result.encode());
        }
        put_hash(&mut o,&self.state_root);
        put_hash(&mut o,&self.proof_root);
        o
    }
    fn signing_bytes(&self,genesis:&Hash)->Vec<u8>{
        let mut o=Vec::new();
        put_hash(&mut o,genesis);put_hash(&mut o,&self.parent);
        put_u64(&mut o,self.slot);put_hash(&mut o,&self.credential);
        o.extend(self.vrf_proof);
        put_hash(&mut o,&self.body_root);
        put_hash(&mut o,&self.state_root);
        put_hash(&mut o,&self.proof_root);
        match &self.archive{
            None=>o.push(0),
            Some(a)=>{o.push(1);a.encode(&mut o)}
        }
        o
    }
    pub fn id(&self,genesis:&Hash)->Hash{
        digest(b"AlgoX/PZ-G1/block-header/v1",
          &[&self.signing_bytes(genesis),&self.kes_signature])
    }
}
pub struct Proposer{
    pub vrf_public:Hash,pub kes_public:Vec<u8>,pub operator:Owner,
    vrf_secret:[u8;64],
    kes_secret:Option<<Sum7Kes as KesAlgorithm>::SigningKey>,
    current_period:u64,
}
impl Proposer{
    pub fn from_seeds(vrf_seed:Hash,kes_seed:Hash,operator:Owner)->PzResult<Self>{
        let (vrf_secret,vrf_public)=VrfDraft03::keypair_from_seed(&vrf_seed);
        let key=Sum7Kes::gen_key_kes_from_seed_bytes(&kes_seed)
            .map_err(|_|Error::InvalidProof)?;
        let kes_public=Sum7Kes::raw_serialize_verification_key_kes(
            &Sum7Kes::derive_verification_key(&key).map_err(|_|Error::InvalidProof)?);
        Ok(Self{vrf_secret,vrf_public,kes_public,operator,
                kes_secret:Some(key),current_period:0})
    }
    pub fn credential(&self,owner:Owner,amount:u64,commission_bps:u16)->Credential {
        Credential{id:Credential::make_id(&owner,&self.vrf_public,&self.kes_public),
                   owner,operator:self.operator,vrf_public:self.vrf_public,
                   kes_public:self.kes_public.clone(),amount,commission_bps,
                   exit_epoch:None,exit_requested_height:None}
    }
    /// Public, nonmutating exact eligibility probe for real independent
    /// owner/operator signers. A slot is admissible only after both the
    /// period-snapshot credential and its cryptographic VRF proof validate;
    /// this does not fabricate an eligible producer or consume KES material.
    pub fn can_produce(&self,chain:&Chain,slot:u64)->PzResult<bool>{
        let epoch=chain.genesis.profile.epoch(slot);
        let credential=chain.snapshot(epoch)?.into_iter().find(|c|
            c.vrf_public==self.vrf_public &&
            c.kes_public==self.kes_public &&
            c.operator==self.operator);
        let Some(credential)=credential else{return Ok(false)};
        let proof=self.prove(chain.genesis.id(),slot,chain.epoch_nonce(epoch))?;
        match chain.eligible(slot,credential.id,proof){
            Ok(_)=>Ok(true),
            Err(Error::Unauthorized)=>Ok(false),
            Err(e)=>Err(e),
        }
    }
    fn prove(&self,genesis:Hash,slot:u64,nonce:Hash)->PzResult<[u8;80]> {
        VrfDraft03::prove(&self.vrf_secret,&vrf_input(genesis,slot,nonce))
            .map_err(|_|Error::InvalidProof)
    }
    fn sign(&mut self,slot:u64,message:&[u8])->PzResult<Vec<u8>>{
        let target=slot;
        if target>=Sum7Kes::total_periods(){return Err(Error::Limit);}
        if target<self.current_period{return Err(Error::InvalidProof);}
        while self.current_period<target{
            let key=self.kes_secret.take().ok_or(Error::InvalidProof)?;
            self.kes_secret=Sum7Kes::update_kes(&(),key,self.current_period)
                .map_err(|_|Error::InvalidProof)?;
            self.current_period+=1;
        }
        let key=self.kes_secret.as_ref().ok_or(Error::InvalidProof)?;
        let sig=Sum7Kes::sign_kes(&(),target,message,key)
            .map_err(|_|Error::InvalidProof)?;
        Ok(Sum7Kes::raw_serialize_signature_kes(&sig))
    }
}
fn vrf_input(genesis:Hash,slot:u64,nonce:Hash)->Hash{
    digest(b"AlgoX/PZ-G1/slot-leader-vrf/v1",
        &[&genesis,&slot.to_le_bytes(),&nonce])
}

#[derive(Clone,Debug)]
pub struct Chain{
    pub genesis:Genesis,pub blocks:Vec<Block>,
    // Full independent replay states, including genesis at index zero.
    pub states:Vec<State>,
}
impl Chain{
    pub fn new(genesis:Genesis)->PzResult<Self>{
        let initial=State::from_genesis(&genesis)?;
        if initial.stake.values().map(|x|x.amount as u128).sum::<u128>()>1024 {
            return Err(Error::Limit); // exact bounded integer election comparison
        }
        Ok(Self{genesis,blocks:Vec::new(),states:vec![initial]})
    }
    pub fn state(&self)->&State{self.states.last().expect("genesis state")}
    pub fn tip(&self)->Hash {
        self.blocks.last().map_or(self.genesis.id(),|b|b.id(&self.genesis.id()))
    }
    pub fn stable_root(&self)->Hash {
        let len=self.blocks.len();
        self.states[len.saturating_sub(self.genesis.profile.k_blocks as usize)].root()
    }
    pub fn stable_proof_root(&self)->PzResult<Hash>{
        let length=self.blocks.len();
        let stable=length.saturating_sub(self.genesis.profile.k_blocks as usize);
        self.states[stable].proof_root()
    }
    pub fn stable_slot(&self)->u64{
        let len=self.blocks.len();
        let stable=len.saturating_sub(self.genesis.profile.k_blocks as usize);
        if stable==0{0}else{self.blocks[stable-1].slot}
    }
    pub fn epoch_nonce(&self,epoch:u64)->Hash{
        let genesis=self.genesis.id();
        if epoch<2{return digest(b"AlgoX/PZ-G1/initial-nonce/v1",
            &[&genesis,&epoch.to_le_bytes()]);}
        let mut nonce=digest(b"AlgoX/PZ-G1/epoch-nonce/v1",
            &[&genesis,&epoch.to_le_bytes()]);
        // Research construction only. Source Praos/Genesis randomness
        // window and grinding bounds must be matched before theorem claims.
        for block in &self.blocks{
            if self.genesis.profile.epoch(block.slot)==epoch-1{
                let output=VrfDraft03::proof_to_hash(&block.vrf_proof)
                    .unwrap_or([0u8;64]);
                nonce=digest(b"AlgoX/PZ-G1/mix-nonce/v1",
                  &[&nonce,&output]);
            }
        }
        nonce
    }
    pub fn snapshot(&self,epoch:u64)->PzResult<Vec<Credential>>{
        let profile=&self.genesis.profile;
        // Epochs 0 and 1 use the explicitly fixed genesis snapshot.
        let reference=&self.states[if epoch<2{0}else{
            let upper=(epoch-1).checked_mul(profile.epoch_slots).ok_or(Error::Overflow)?;
            self.blocks.iter().take_while(|b|b.slot<upper).count()
        }];
        let eligible=reference.stake.values().filter(|x|{
            epoch<2 || x.exit_epoch.is_none_or(|exit|exit>epoch-2)
        }).cloned().collect::<Vec<_>>();
        Ok(eligible)
    }
    fn eligible(&self,slot:u64,id:Hash,proof:[u8;80])->PzResult<(Credential,[u8;64])>{
        let p=&self.genesis.profile;
        if slot==0 || slot>p.horizon || self.blocks.last().is_some_and(|b|slot<=b.slot){
            return Err(Error::InvalidBlock);
        }
        let epoch=p.epoch(slot);
        let roster=self.snapshot(epoch)?;
        let total: u64=roster.iter().try_fold(0u64,|acc,x|
            acc.checked_add(x.amount).ok_or(Error::Overflow))?;
        let cred=roster.into_iter().find(|x|x.id==id).ok_or(Error::Unauthorized)?;
        let output=VrfDraft03::verify(&cred.vrf_public,&proof,
            &vrf_input(self.genesis.id(),slot,self.epoch_nonce(epoch)))
            .map_err(|_|Error::InvalidProof)?;
        let sample=u64::from_be_bytes(output[..8].try_into().map_err(|_|Error::Malformed)?);
        if !wins(sample,cred.amount,total,p.f_num,p.f_den)?{
            return Err(Error::Unauthorized);
        }
        Ok((cred,output))
    }
    pub fn archive_challenge(&self,slot:u64,vrf_output:&[u8;64])
        ->PzResult<Option<(usize,usize)>>{
        let k=self.genesis.profile.k_blocks as usize;
        let eligible=self.blocks.len().saturating_sub(k);
        if eligible==0{return Ok(None);}
        let randomness=digest(b"AlgoX/PZ-G1/archive-challenge/v1",
            &[&self.genesis.id(),&self.tip(),&slot.to_le_bytes(),vrf_output]);
        // Do ALL entropy reduction in an explicitly fixed-width integer
        // domain, then convert the bounded remainder to a native index.
        // Taking `as usize % eligible` first silently truncates the high
        // 32 bits in wasm32, producing a different historical challenge
        // than native 64-bit validators when eligible is not a power of 2.
        let eligible64=u64::try_from(eligible).map_err(|_|Error::Limit)?;
        let selected=u64::from_be_bytes(randomness[..8].try_into().unwrap())%eligible64;
        let selected=usize::try_from(selected).map_err(|_|Error::Limit)?;
        let bytes=self.blocks[selected].body_bytes();
        let count=bytes.len().div_ceil(CHUNK);
        if count==0{return Err(Error::InvalidBlock);}
        let count64=u64::try_from(count).map_err(|_|Error::Limit)?;
        let chunk=u64::from_be_bytes(randomness[8..16].try_into().unwrap())%count64;
        let chunk=usize::try_from(chunk).map_err(|_|Error::Limit)?;
        Ok(Some((selected,chunk)))
    }
    pub fn build_archive_response(&self,slot:u64,vrf_output:&[u8;64])
        ->PzResult<Option<ArchiveResponse>>{
        let Some((selected,chunk))=self.archive_challenge(slot,vrf_output)? else {
            return Ok(None);
        };
        let material=self.blocks[selected].body_bytes();
        let (bytes,path)=proof(&material,chunk)?;
        Ok(Some(ArchiveResponse{historic_height:selected as u64+1,
            chunk_index:chunk as u32,bytes,path}))
    }
    fn verify_archive(&self,slot:u64,vrf_output:&[u8;64],
            evidence:&Option<ArchiveResponse>)->PzResult<bool>{
        let Some(e)=evidence else{return Ok(false);};
        let (selected,chunk)=self.archive_challenge(slot,vrf_output)?
            .ok_or(Error::InvalidProof)?;
        if e.historic_height!=selected as u64+1 ||
           e.chunk_index as usize!=chunk ||
           e.bytes.len()>self.genesis.profile.max_archive_bytes{
            return Err(Error::InvalidProof);
        }
        let material=self.blocks[selected].body_bytes();
        verify_chunk(&self.blocks[selected].body_root,
            material.len(),chunk,&e.bytes,&e.path)?;
        Ok(true)
    }
    fn transition(&self,block:&Block,cred:&Credential,data_bonus:bool)
        ->PzResult<(State,Vec<Outcome>)>{
        let p=&self.genesis.profile;
        if block.events.len()>p.max_block_events{return Err(Error::Limit);}
        let mut state=self.state().clone();
        let parent_height=state.height;
        let mut results=Vec::new();
        // One bounded processing budget across both already-overdue work and
        // freshly matured rights. A long outage cannot cause double budget
        // consumption or let fresh elective actions starve older obligations.
        let mut due_budget=p.max_due_per_block;
        if state.due_backlog(block.slot) {
            let processed=state.process_due(p,block.slot-1,due_budget)?;
            due_budget-=processed;
            if state.due_backlog(block.slot) && !block.events.is_empty() {
                return Err(Error::InvalidBlock);
            }
        }
        let maxbytes:usize=block.events.iter().map(|x|x.encoded().len()).sum();
        if maxbytes>p.max_archive_bytes{return Err(Error::Limit);}
        for (index,event) in block.events.iter().enumerate() {
            let outcome=state.apply(p,event,block.slot,parent_height,
                u32::try_from(index).map_err(|_|Error::Limit)?,cred.operator,self.stable_slot())?;
            results.push(outcome);
        }
        state.process_due(p,block.slot,due_budget)?;
        state.height=parent_height.checked_add(1).ok_or(Error::Overflow)?;
        state.slot=block.slot;
        state.issue(p.issue_base,if data_bonus{p.issue_data}else{0},
                    cred.owner,cred.operator,cred.commission_bps)?;
        state.assert_supply(&self.genesis)?;
        Ok((state,results))
    }
    /// Nonmutating Phase Zero fault-location instrumentation, not consensus.
    #[cfg(feature = "pz-g1-diagnostics")]
    pub fn diagnose_wire(&self,wire:&[u8])->[u8;2] {
        let block=match Block::decode_wire(wire,&self.genesis.profile){
            Ok(b)=>b,Err(e)=>return [1,e as u8]
        };
        let (cred,vrf)=match self.eligible(block.slot,block.credential,block.vrf_proof){
            Ok(x)=>x,Err(e)=>return [2,e as u8]
        };
        if block.parent!=self.tip(){return [3,Error::InvalidBlock as u8];}
        let data=match self.verify_archive(block.slot,&vrf,&block.archive){
            Ok(v)=>v,Err(e)=>return [4,e as u8]
        };
        let (next,results)=match self.transition(&block,&cred,data){
            Ok(x)=>x,Err(e)=>return [5,e as u8]
        };
        if results!=block.results || next.root()!=block.state_root {
            return [6,Error::InvalidBlock as u8];
        }
        match next.proof_root(){
            Ok(root) if root==block.proof_root=>{},
            Ok(_)=>return [7,Error::InvalidBlock as u8],
            Err(e)=>return [7,e as u8],
        }
        if block.body_root!=merkle_root(&block.body_bytes()){
            return [8,Error::InvalidBlock as u8];
        }
        let Some(pk)=Sum7Kes::raw_deserialize_verification_key_kes(&cred.kes_public)
            else{return [9,Error::InvalidProof as u8]};
        let Some(sig)=Sum7Kes::raw_deserialize_signature_kes(&block.kes_signature)
            else{return [10,Error::InvalidProof as u8]};
        match Sum7Kes::verify_kes(&(),&pk,block.slot,
            &block.signing_bytes(&self.genesis.id()),&sig){
            Ok(_)=>[0,0],
            Err(_)=>[11,Error::InvalidProof as u8],
        }
    }
    fn verify_producer_header(&self,block:&Block,credential:&Credential)
        ->PzResult<()>{
        let pubkey=Sum7Kes::raw_deserialize_verification_key_kes(
            &credential.kes_public).ok_or(Error::InvalidProof)?;
        let signature=Sum7Kes::raw_deserialize_signature_kes(
            &block.kes_signature).ok_or(Error::InvalidProof)?;
        Sum7Kes::verify_kes(&(),&pubkey,block.slot,
            &block.signing_bytes(&self.genesis.id()),&signature)
            .map_err(|_|Error::InvalidProof)
    }
    pub fn append(&mut self,block:Block)->PzResult<()>{
        let (credential,output)=self.eligible(block.slot,block.credential,block.vrf_proof)?;
        if block.parent!=self.tip(){return Err(Error::InvalidBlock);}
        // The credential's epoch-eligible KES signature binds all economic
        // roots, body commitment, archive witness and the parent. Reject
        // unauthenticated proposals before expensive data-proof construction,
        // full Core execution or fee-bearing economic replay.
        self.verify_producer_header(&block,&credential)?;
        let data=self.verify_archive(block.slot,&output,&block.archive)?;
        let (state,results)=self.transition(&block,&credential,data)?;
        if results!=block.results || state.root()!=block.state_root ||
           state.proof_root()?!=block.proof_root ||
           block.body_root!=merkle_root(&block.body_bytes()){
            return Err(Error::InvalidBlock);
        }
        self.blocks.push(block);
        self.states.push(state);
        Ok(())
    }
    pub fn produce(&mut self,producer:&mut Proposer,slot:u64,events:Vec<SignedEvent>,
                   include_archive:bool)->PzResult<Hash>{
        let id=self.snapshot(self.genesis.profile.epoch(slot))?.into_iter()
            .find(|c|c.vrf_public==producer.vrf_public &&
                      c.kes_public==producer.kes_public &&
                      c.operator==producer.operator)
            .ok_or(Error::Unauthorized)?.id;
        let proof=producer.prove(self.genesis.id(),slot,
            self.epoch_nonce(self.genesis.profile.epoch(slot)))?;
        let (cred,output)=self.eligible(slot,id,proof)?;
        let archive=if include_archive{self.build_archive_response(slot,&output)?}else{None};
        let mut block=Block{
            slot,credential:id,vrf_proof:proof,events,results:Vec::new(),
            archive,body_root:[0;32],state_root:[0;32],
            proof_root:[0;32],parent:self.tip(),
            kes_signature:Vec::new()
        };
        let data=self.verify_archive(slot,&output,&block.archive)?;
        let (state,results)=self.transition(&block,&cred,data)?;
        block.results=results;
        block.state_root=state.root();
        block.proof_root=state.proof_root()?;
        block.body_root=merkle_root(&block.body_bytes());
        block.kes_signature=producer.sign(slot,&block.signing_bytes(&self.genesis.id()))?;
        let digest=block.id(&self.genesis.id());
        self.append(block)?;Ok(digest)
    }
    pub fn replay(genesis:Genesis,blocks:&[Block])->PzResult<Self>{
        let mut chain=Self::new(genesis)?;
        for b in blocks{chain.append(b.clone())?;}
        Ok(chain)
    }
    pub fn verify_checkpoint(&self,claimed:&State,at_height:usize)->PzResult<()>{
        let correct=self.states.get(at_height).ok_or(Error::Unknown)?;
        // A matching digest cannot authorize uncommitted mutable caches.
        // Check all due-payment and original-priority indexes before a state
        // can be recognized as a complete authenticated checkpoint.
        claimed.validate_indexes()?;
        if claimed.genesis!=self.genesis.id() || claimed.root()!=correct.root() {
            return Err(Error::InvalidProof);
        }
        Ok(())
    }
}

/// History selection over two independently fully verified research chains.
/// Near divergence: longest valid chain. Deep divergence: strictly denser
/// first s post-intersection slots. This is an explicit *research comparator*
/// not an assertion that we implemented the source maxvalid-bg peer iterator,
/// synchronous-network assumptions or partial-candidate rules exactly.
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub enum Preference{Keep,Switch,NeedHistory}
/// Source-style finite window selection with a separately authenticated
/// observation clock. An honest sparse chain need not manufacture a block at
/// the end of the s-slot window just to establish that those slots elapsed.
/// Every compared candidate must already be independently fully replayed.
pub fn prefer_at_slot(current:&Chain,alternative:&Chain,observed_slot:u64)
    ->PzResult<Preference>{
    if current.genesis.id()!=alternative.genesis.id(){return Err(Error::InvalidBlock);}
    if current.blocks.last().is_some_and(|b|b.slot>observed_slot) ||
       alternative.blocks.last().is_some_and(|b|b.slot>observed_slot){
        return Err(Error::InvalidBlock);
    }
    let common=current.blocks.iter().zip(&alternative.blocks)
        .take_while(|(a,b)|a.id(&current.genesis.id())==b.id(&current.genesis.id())).count();
    if common==alternative.blocks.len(){return Ok(Preference::Keep);}
    if current.blocks.len()-common<=current.genesis.profile.k_blocks as usize{
        return Ok(if alternative.blocks.len()>current.blocks.len(){
            Preference::Switch
        }else{Preference::Keep});
    }
    let window=current.genesis.profile.s_slots;
    let intersection=if common==0{0}else{current.blocks[common-1].slot};
    let end=intersection.checked_add(window).ok_or(Error::Overflow)?;
    if observed_slot<end{return Ok(Preference::NeedHistory);}
    let density=|chain:&Chain|{
        chain.blocks[common..].iter().filter(|b|
            b.slot>intersection&&b.slot<=end).count()
    };
    Ok(if density(alternative)>density(current){
        Preference::Switch
    }else{Preference::Keep})
}
/// Legacy comparison when no independent contemporary clock was supplied:
/// only count the density window once both fully validated candidate chains
/// reach its end. Rejoining nodes should use prefer_at_slot with host time.
pub fn prefer(current:&Chain,alternative:&Chain)->PzResult<Preference>{
    if current.genesis.id()!=alternative.genesis.id(){return Err(Error::InvalidBlock);}
    let current_slot=current.blocks.last().map_or(0,|b|b.slot);
    let alternative_slot=alternative.blocks.last().map_or(0,|b|b.slot);
    let common=current.blocks.iter().zip(&alternative.blocks)
        .take_while(|(a,b)|a.id(&current.genesis.id())==b.id(&current.genesis.id())).count();
    if common!=alternative.blocks.len() &&
       current.blocks.len()-common>current.genesis.profile.k_blocks as usize{
        let intersection=if common==0{0}else{current.blocks[common-1].slot};
        let end=intersection.checked_add(current.genesis.profile.s_slots)
            .ok_or(Error::Overflow)?;
        if current_slot<end || alternative_slot<end {
            return Ok(Preference::NeedHistory);
        }
    }
    prefer_at_slot(current,alternative,current_slot.max(alternative_slot))
}
pub fn select_received(genesis:Genesis,candidates:&[Vec<Block>])
    ->PzResult<Chain>{
    let mut selected=Chain::new(genesis.clone())?;
    let mut found=false;
    for candidate in candidates{
        let Ok(verified)=Chain::replay(genesis.clone(),candidate) else{continue;};
        if !found{selected=verified;found=true;continue;}
        match prefer(&selected,&verified)? {
            Preference::Keep=>{},
            Preference::Switch=>selected=verified,
            Preference::NeedHistory=>{
                // A deep-fork density comparison with an incomplete window
                // is NOT evidence for retaining the presently selected root.
                // Fetch enough independently valid historical data or fail
                // closed; do not silently accept a stale advertised history.
                return Err(Error::Unavailable);
            }
        }
    }
    if !found{return Err(Error::Unavailable);}
    Ok(selected)
}

/// Fully validated received candidates compared after a trusted host clock
/// has reached the specified slot. Invalid or future-advertised histories
/// cannot nominate their own clock. A deep window still in the future is
/// unresolved, rather than a false longest-chain finality certificate.
pub fn select_received_at_slot(genesis:Genesis,candidates:&[Vec<Block>],
    observed_slot:u64)->PzResult<Chain>{
    let mut selected=Chain::new(genesis.clone())?;
    let mut found=false;
    for history in candidates{
        if history.last().is_some_and(|b|b.slot>observed_slot){continue;}
        let Ok(verified)=Chain::replay(genesis.clone(),history) else{continue;};
        if !found{selected=verified;found=true;continue;}
        match prefer_at_slot(&selected,&verified,observed_slot)?{
            Preference::Keep=>{},
            Preference::Switch=>selected=verified,
            Preference::NeedHistory=>return Err(Error::Unavailable),
        }
    }
    if !found{return Err(Error::Unavailable);}
    Ok(selected)
}
