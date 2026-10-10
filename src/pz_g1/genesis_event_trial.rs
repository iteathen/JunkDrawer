//! Experiment 023 — event-driven, conditional Genesis synchronization laboratory.
//!
//! This module NEVER selects a branch, disconnects a real socket, exercises an
//! economic right, or asserts that a Cardano/Ouroboros theorem transfers.
//! Header poll replies are untrusted until a SEPARATE complete original-genesis
//! economic replay corroborates their *exact observed prefix*.
//!
//! HAA/known-honest identity, k, s, latency and resource bounds are explicitly
//! LABORATORY assumptions. In particular keys, peer count and HAA simulation
//! cannot confer governance/finality or personhood.
use super::{Chain,Genesis,Error,Hash,PzResult};
use super::chain_sync_observe::{Observed,PeerCursor,Reply};
use super::genesis_sync_trial::{self,GsmMode,HeaderState,HaaEvidence,PeerView,SyncTrace};
use std::collections::BTreeMap;

#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct Parameters {
    pub max_peers:usize,
    pub max_events:usize,
    pub patience_capacity_ms:u64,
    pub patience_refill_ms:u64,
    pub max_assumed_rtt_ms:u64,
    pub max_await_age_ms:u64,
    pub gdd_cooldown_ms:u64,
}
impl Parameters {
    pub fn finite_control()->Self {
        Self{max_peers:16,max_events:2048,patience_capacity_ms:6000,
            patience_refill_ms:250,max_assumed_rtt_ms:1500,
            max_await_age_ms:1500,gdd_cooldown_ms:1000}
    }
    fn check(&self)->PzResult<()> {
        if self.max_peers==0 || self.max_peers>128 ||
           self.max_events==0 || self.max_events>65536 ||
           self.patience_capacity_ms==0 || self.max_assumed_rtt_ms==0 ||
           self.max_await_age_ms==0 {
            return Err(Error::Limit);
        }
        Ok(())
    }
}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub enum Reason {
    Connect, ObservedForward, ObservedAwait, ObservedRollback,
    VerifiedBody, HeaderRejected, LatencyBoundExceeded, PatienceExpired,
    GddCandidate, GddAmbiguous, GddDisconnected, HaaWithdrawn,
    ModePreSyncing, ModeSyncing, ModeCaughtUp, LocalSelectionObserved,
}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct Recorded {
    pub time_ms:u64,pub observed_slot:u64,pub id:Option<u16>,pub why:Reason,
}
#[derive(Clone)]
struct Peer {
    cursor:PeerCursor,
    confirmed:Option<Chain>,
    patience_ms:u64,
    highest_seen:usize,
    forecast_blocked:bool,
    poll_started:Option<u64>,
    last_await_ms:Option<u64>,
}
impl Peer {
    fn new(genesis:Hash,p:Parameters)->Self {
        Self{cursor:PeerCursor::new(genesis),confirmed:None,
            patience_ms:p.patience_capacity_ms,highest_seen:0,
            forecast_blocked:false,poll_started:None,
            last_await_ms:None}
    }
}
#[derive(Clone,Debug)]
pub struct Snapshot {
    pub mode:GsmMode,
    pub observed_slot:u64,
    pub active_peers:Vec<u16>,
    pub observed_headers:Vec<(u16,usize,bool)>,
    pub pending_economic_replay:Vec<u16>,
    pub honest_source_assumed:Option<u16>,
    pub honest_source_available:bool,
    pub assumed_latency_violations:u64,
    /// A test-designated honest upstream exceeded the separately specified
    /// poll RTT hypothesis. NOT direct proof that network-wide Delta failed.
    pub honest_poll_bound_breached:bool,
    pub honest_growth_and_dominance:Option<bool>,
    pub source_trial:Option<SyncTrace>,
    pub drops_unsafe_or_unresolved:bool,
    pub proposed_gdd_drops:Vec<u16>,
    pub event_loss:u64,
}
pub struct EventDriven {
    genesis:Genesis,
    local:Chain,
    immutable:usize,
    pub mode:GsmMode,
    config:Parameters,
    peers:BTreeMap<u16,Peer>,
    pub observed_slot:u64,
    pub now_ms:u64,
    honest_source_assumed:Option<u16>,
    latency_violations:u64,
    honest_poll_bound_breached:bool,
    last_gdd_ms:Option<u64>,
    events:Vec<Recorded>,
    event_loss:u64,
}
impl EventDriven {
    pub fn new(local:&Chain,immutable:usize,config:Parameters)->PzResult<Self> {
        config.check()?;
        // Reconstruct the entire economic chain; never trust the caller's
        // cached state-root, balances, or host-selected histories.
        let verified=Chain::replay(local.genesis.clone(),&local.blocks)?;
        if immutable>verified.blocks.len(){return Err(Error::Limit);}
        Ok(Self{genesis:local.genesis.clone(),local:verified,immutable,
            mode:GsmMode::PreSyncing,config,peers:BTreeMap::new(),
            observed_slot:0,now_ms:0,honest_source_assumed:None,
            latency_violations:0,honest_poll_bound_breached:false,
            last_gdd_ms:None,
            events:Vec::new(),event_loss:0})
    }
    pub fn records(&self)->&[Recorded]{&self.events}
    fn log(&mut self,id:Option<u16>,why:Reason) {
        if self.events.len()>=self.config.max_events {
            self.event_loss+=1;
        }else{
            self.events.push(Recorded{time_ms:self.now_ms,
                observed_slot:self.observed_slot,id,why});
        }
    }
    fn effective_haa(&self)->HaaEvidence{
        match self.honest_source_assumed {
            Some(id) if self.peers.contains_key(&id) &&
                !self.honest_poll_bound_breached=>HaaEvidence::ExternallyAssumed,
            _=>HaaEvidence::Unestablished,
        }
    }
    pub fn connect(&mut self,id:u16)->PzResult<()> {
        if self.peers.contains_key(&id){return Err(Error::Duplicate);}
        if self.peers.len()>=self.config.max_peers{return Err(Error::Limit);}
        self.peers.insert(id,Peer::new(self.genesis.id(),self.config));
        self.log(Some(id),Reason::Connect);
        self.refresh_mode()?;
        Ok(())
    }
    /// Explicit laboratory world assumption, not a network-produced proof:
    /// the chosen peer is honest, already caught-up and delay-bounded.
    /// Tests MUST inspect honest chain-growth and relative-density separately.
    pub fn assume_honest_upstream(&mut self,id:u16)->PzResult<()> {
        if !self.peers.contains_key(&id){return Err(Error::Unknown);}
        self.honest_source_assumed=Some(id);
        self.honest_poll_bound_breached=false;
        self.refresh_mode()
    }
    pub fn withdraw_haa(&mut self)->PzResult<()> {
        self.honest_source_assumed=None;
        self.log(None,Reason::HaaWithdrawn);
        self.refresh_mode()
    }
    /// Lab clock is monotonic, independent of any signed peer timestamp.
    /// LoP drips ONLY while Syncing, not AwaitReply, and not explicitly
    /// blocked beyond the forecast horizon. Tests control blocked state.
    pub fn advance(&mut self,time_ms:u64,slot:u64)->PzResult<()>{
        if time_ms<self.now_ms || slot<self.observed_slot ||
           slot>self.genesis.profile.horizon {return Err(Error::InvalidBlock);}
        let elapsed=time_ms-self.now_ms;
        self.now_ms=time_ms;self.observed_slot=slot;
        if self.mode==GsmMode::Syncing {
            let mut expired=Vec::new();
            for (&id,p) in self.peers.iter_mut(){
                if p.cursor.awaiting() || p.forecast_blocked {continue;}
                p.patience_ms=p.patience_ms.saturating_sub(elapsed);
                if p.patience_ms==0{expired.push(id);}
            }
            for id in expired {
                self.peers.remove(&id);
                // A previously assumed honest upstream that times out is
                // not re-authorized merely by reconnecting under the same
                // key. Only a fresh explicit test-world HAA can restore it.
                if self.honest_source_assumed==Some(id) {
                    self.honest_source_assumed=None;
                    self.log(Some(id),Reason::HaaWithdrawn);
                }
                self.log(Some(id),Reason::PatienceExpired);
            }
        }
        self.refresh_mode()
    }
    pub fn mark_outside_forecast(&mut self,id:u16,blocked:bool)->PzResult<()>{
        self.peers.get_mut(&id).ok_or(Error::Unknown)?.forecast_blocked=blocked;
        Ok(())
    }
    pub fn begin_poll(&mut self,id:u16)->PzResult<Vec<u8>> {
        let p=self.peers.get_mut(&id).ok_or(Error::Unknown)?;
        if p.poll_started.is_some(){return Err(Error::Duplicate);}
        p.poll_started=Some(self.now_ms);
        Ok(p.cursor.query())
    }
    pub fn observe(&mut self,id:u16,reply:Reply,
                   time_ms:u64,slot:u64)->PzResult<Observed>{
        // Keep the last poll started under the previous time/slot; time
        // advances before processing the reply, so LoP may expire a peer.
        self.advance(time_ms,slot)?;
        let p=self.peers.get_mut(&id).ok_or(Error::Unavailable)?;
        let began=p.poll_started.ok_or(Error::Unauthorized)?;
        let rtt=time_ms.checked_sub(began).ok_or(Error::InvalidBlock)?;
        let mut new_cursor=p.cursor.clone();
        let observation=new_cursor.observe(reply,slot,
            self.genesis.profile.horizon as usize);
        if let Err(e)=observation {
            p.poll_started=None;
            self.log(Some(id),Reason::HeaderRejected);
            return Err(e);
        }
        let result=observation?;
        let previous_max=p.highest_seen;
        let height=new_cursor.height();
        p.cursor=new_cursor;
        p.poll_started=None;
        p.last_await_ms=match result {
            Observed::Await|Observed::RepeatedAwait=>Some(self.now_ms),
            _=>None,
        };
        if height>previous_max {
            p.highest_seen=height;
            p.patience_ms=p.patience_ms.saturating_add(self.config.patience_refill_ms)
                .min(self.config.patience_capacity_ms);
        }
        // New observed header/rollback can invalidate previous confirmation.
        if p.confirmed.as_ref().is_some_and(|c|
            c.blocks.len()!=height || !p.cursor.matches_verified_chain(c)){
            p.confirmed=None;
        }
        if rtt>self.config.max_assumed_rtt_ms {
            self.latency_violations+=1;
            if self.honest_source_assumed==Some(id){
                // Loss of this *laboratory* timing premise makes the model's
                // GDD safety precondition unqualified; the network would
                // need actual honest propagation bounds independently.
                self.honest_poll_bound_breached=true;
            }
            self.log(Some(id),Reason::LatencyBoundExceeded);
        }
        self.log(Some(id),match result {
            Observed::Forward=>Reason::ObservedForward,
            Observed::Await|Observed::RepeatedAwait=>Reason::ObservedAwait,
            Observed::Rollback=>Reason::ObservedRollback,
        });
        self.refresh_mode()?;
        Ok(result)
    }
    /// Never let a fully valid but incompatible peer history cross an
    /// independently supplied immutable-prefix boundary. This prefix is a
    /// *test premise*, not an authority derived from advertised root bytes.
    fn extends_immutable(&self,other:&Chain)->bool{
        if self.immutable>other.blocks.len(){return false;}
        let genesis=self.genesis.id();
        self.local.blocks.iter().take(self.immutable)
            .zip(other.blocks.iter().take(self.immutable))
            .all(|(a,b)|a.id(&genesis)==b.id(&genesis))
    }
    /// The origin of the bytes is untrusted. All economic state and the
    /// exact block-header prefix are independently checked, and the supplied
    /// selected root has NO authority over the local node's selection.
    pub fn correlate_full_history(&mut self,id:u16,history:&Chain)->PzResult<()>{
        let verified=Chain::replay(self.genesis.clone(),&history.blocks)?;
        if !self.extends_immutable(&verified) {
            return Err(Error::InvalidBlock);
        }
        let p=self.peers.get(&id).ok_or(Error::Unknown)?;
        if verified.blocks.len()!=p.cursor.height() ||
           !p.cursor.matches_verified_chain(&verified){
            return Err(Error::InvalidProof);
        }
        self.peers.get_mut(&id).ok_or(Error::Unknown)?.confirmed=Some(verified);
        self.log(Some(id),Reason::VerifiedBody);
        self.refresh_mode()
    }
    /// Only observe a separately verified local economic history. No
    /// operator, peer header or source trial ever selects one for the ledger.
    pub fn observe_local_selection(&mut self,history:&Chain)->PzResult<()>{
        let verified=Chain::replay(self.genesis.clone(),&history.blocks)?;
        if !self.extends_immutable(&verified){
            return Err(Error::InvalidBlock);
        }
        self.local=verified;
        self.log(None,Reason::LocalSelectionObserved);
        self.refresh_mode()
    }
    fn views(&self)->Option<Vec<PeerView<'_>>>{
        let mut v=Vec::new();
        for (&id,p) in &self.peers {
            let c=p.confirmed.as_ref()?;
            if !p.cursor.matches_verified_chain(c) {return None;}
            // In short-poll mode an old AwaitReply cannot be used forever
            // as if it described a simultaneous current ChainSync state.
            let recent_await=p.cursor.awaiting() &&
                p.last_await_ms.is_some_and(|observed|
                    self.now_ms.saturating_sub(observed)<=self.config.max_await_age_ms);
            v.push(PeerView{id,history:c,header_state:if recent_await{
                HeaderState::AwaitingReply
            }else{HeaderState::Advertising}});
        }
        if v.is_empty(){None}else{Some(v)}
    }
    fn trial_trace(&self)->PzResult<Option<SyncTrace>>{
        let Some(v)=self.views() else {return Ok(None);};
        genesis_sync_trial::trace(&self.local,&v,self.immutable,self.observed_slot,self.mode)
            .map(Some)
    }
    fn refresh_mode(&mut self)->PzResult<()>{
        let old=self.mode;
        if self.mode==GsmMode::PreSyncing {
            if self.effective_haa()==HaaEvidence::ExternallyAssumed{
                self.mode=GsmMode::Syncing;
            }
        }else if self.mode==GsmMode::Syncing{
            if self.effective_haa()==HaaEvidence::Unestablished{
                self.mode=GsmMode::PreSyncing;
            }else if let Some(views)=self.views(){
                let trace=genesis_sync_trial::trace(&self.local,&views,
                    self.immutable,self.observed_slot,self.mode)?;
                // A pending poll or expired AwaitReply defeats the short-
                // poll model's simultaneous exhausted-header observation.
                // This never authorizes ledger selection or chain rollback.
                if !self.peers.values().any(|p|p.poll_started.is_some()) &&
                   views.iter().all(|v|v.header_state==HeaderState::AwaitingReply){
                    self.mode=genesis_sync_trial::next_mode(
                        self.mode,self.effective_haa(),false,
                        &self.local,&views,&trace);
                }
            }
        }
        // A previously CaughtUp node is intentionally NOT dragged back to
        // Syncing just because its HAA source disappears: No Praos Disruption.
        // Staleness must be a separate test-supplied signal.
        if self.mode!=old {
            self.log(None,match self.mode{
                GsmMode::PreSyncing=>Reason::ModePreSyncing,
                GsmMode::Syncing=>Reason::ModeSyncing,
                GsmMode::CaughtUp=>Reason::ModeCaughtUp,
            });
        }
        Ok(())
    }
    pub fn mark_caught_up_stale(&mut self)->PzResult<()>{
        if self.mode==GsmMode::CaughtUp{
            self.mode=GsmMode::PreSyncing;
            self.log(None,Reason::ModePreSyncing);
        }
        self.refresh_mode()
    }
    /// Test-only source assumptions:
    /// 1) honest peer exists, has independently replayed candidate bytes;
    /// 2) after every relevant competing intersection, its early-window
    ///    density strictly exceeds the rival's density;
    /// 3) honest peer grew more than k blocks in that source window.
    /// These conditions CANNOT be established from a peer's own signature.
    pub fn honest_growth_and_dominance(&self)->Option<bool>{
        let honest_id=self.honest_source_assumed?;
        let honest=self.peers.get(&honest_id)?.confirmed.as_ref()?;
        let peers=self.views()?;
        let k=self.genesis.profile.k_blocks as usize;
        let s=self.genesis.profile.s_slots;
        for p in peers.iter().filter(|x|x.id!=honest_id){
            let shared=honest.blocks.iter().zip(&p.history.blocks)
                .take_while(|(x,y)|x.id(&self.genesis.id())==y.id(&self.genesis.id()))
                .count();
            if shared==p.history.blocks.len(){continue;}
            let start=if shared==0{0}else{honest.blocks[shared-1].slot};
            let end=start.checked_add(s)?;
            let h=honest.blocks[shared..].iter()
                .filter(|b|b.slot>start && b.slot<=end).count();
            let other=p.history.blocks[shared..].iter()
                .filter(|b|b.slot>start && b.slot<=end).count();
            if h<=k || h<=other {return Some(false);}
        }
        Some(true)
    }
    pub fn snapshot(&self)->PzResult<Snapshot>{
        let trace=self.trial_trace()?;
        let gdd=trace.as_ref().map_or_else(Vec::new,
            |t|t.proposed_drops.clone());
        let ambiguous=trace.as_ref().is_some_and(|t|t.all_dropped);
        Ok(Snapshot{
            mode:self.mode,observed_slot:self.observed_slot,
            active_peers:self.peers.keys().copied().collect(),
            observed_headers:self.peers.iter().map(|(&id,p)|
                (id,p.cursor.height(),p.cursor.awaiting())).collect(),
            pending_economic_replay:self.peers.iter().filter_map(|(&id,p)|
                p.confirmed.is_none().then_some(id)).collect(),
            honest_source_assumed:self.honest_source_assumed,
            honest_source_available:self.effective_haa()==HaaEvidence::ExternallyAssumed,
            assumed_latency_violations:self.latency_violations,
            honest_poll_bound_breached:self.honest_poll_bound_breached,
            honest_growth_and_dominance:self.honest_growth_and_dominance(),
            source_trial:trace,drops_unsafe_or_unresolved:ambiguous,
            proposed_gdd_drops:gdd,event_loss:self.event_loss,
        })
    }
    /// This explicitly LAB-ONLY disconnection exercises event-by-event GDD.
    /// A failed honest-growth premise or a simultaneous all-peer GDD proposal
    /// causes refusal, not arbitrary source-incompatible ledger selection.
    pub fn disconnect_one_gdd(&mut self,id:u16)->PzResult<()>{
        if self.mode!=GsmMode::Syncing ||
           self.effective_haa()!=HaaEvidence::ExternallyAssumed ||
           self.honest_growth_and_dominance()!=Some(true) ||
           self.honest_poll_bound_breached {
            return Err(Error::Unavailable);
        }
        let diagnostic=self.snapshot()?;
        if diagnostic.drops_unsafe_or_unresolved{
            self.log(Some(id),Reason::GddAmbiguous);
            return Err(Error::Unavailable);
        }
        if !diagnostic.proposed_gdd_drops.contains(&id){
            return Err(Error::InvalidProof);
        }
        if self.last_gdd_ms.is_some_and(|old|
            self.now_ms.saturating_sub(old)<self.config.gdd_cooldown_ms){
            return Err(Error::Unavailable);
        }
        self.log(Some(id),Reason::GddCandidate);
        self.peers.remove(&id);
        if self.honest_source_assumed==Some(id){
            self.honest_source_assumed=None;
            self.log(Some(id),Reason::HaaWithdrawn);
        }
        self.last_gdd_ms=Some(self.now_ms);
        self.log(Some(id),Reason::GddDisconnected);
        self.refresh_mode()
    }
}
