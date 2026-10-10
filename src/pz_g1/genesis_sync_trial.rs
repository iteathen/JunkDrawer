//! Experiment 021: READ-ONLY, source-oriented Genesis sync diagnostic.
//!
//! This is a deliberately incomplete *correspondence trial*, not the Cardano
//! implementation, the maxvalid-bg proof, a deployable GSM, or a new way to
//! choose a canonical AlgoX economic history. It makes the three-mode/GDD/LoE
//! assumptions observable over FULLY REPLAYED PZ-G1 histories.
//!
//! The HAA is an EXTERNAL environmental assumption: a peer signature, a
//! locator, an observed tip and a host wall clock do not establish it.
//! No function here changes a live Chain, selects a paid claimant, or votes.
//! See prototype/research/experiment-021-canonical-history-convergence-source-trial.md.
use super::{Chain,Error,PzResult,Hash};
use std::collections::BTreeSet;

/// High-level state names from the Cardano Genesis State Machine. The finite
/// transition control below is intentionally MORE conservative than Cardano:
/// it does not implement the persistent caught-up marker, CSJ, LoP or DBF.
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub enum GsmMode { PreSyncing, Syncing, CaughtUp }

/// NOT something peer signatures can establish. Only the test environment
/// declares the stated honest-upstream availability assumption; production
/// must independently justify its P2P/delay/stake model.
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub enum HaaEvidence { Unestablished, ExternallyAssumed }

#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub enum HeaderState { Advertising, AwaitingReply }

/// The caller MUST independently replay each chain from the pinned genesis.
/// The values are diagnostic test data; peer ID and status are not authority.
#[derive(Clone,Copy)]
pub struct PeerView<'a> {
    pub id:u16,
    pub history:&'a Chain,
    pub header_state:HeaderState,
}

#[derive(Clone,Debug,Eq,PartialEq)]
pub struct GddPair {
    pub rejected_peer:u16,
    pub compared_to:u16,
    pub anchor_blocks:usize,
    pub anchor_slot:u64,
    pub end_slot:u64,
    pub weak_density:usize,
    pub strong_density:usize,
    pub weak_upper_bound:usize,
    pub strong_after_anchor:usize,
}

/// One candidate-per-peer pure diagnostic, not a network disconnector.
#[derive(Clone,Debug,Eq,PartialEq)]
pub struct SyncTrace {
    pub mode:GsmMode,
    pub connected_peers:usize,
    pub loe_before:Option<usize>,
    pub loe_after:Option<usize>,
    pub select_ceiling:Option<usize>,
    pub gdd_candidates:Vec<GddPair>,
    pub proposed_drops:Vec<u16>,
    pub retained_peers:Vec<u16>,
    /// If true, a naive simultaneous GDD application would discard *every*
    /// view. The real implementation is event-driven; this is not an order
    /// or liveness recommendation.
    pub all_dropped:bool,
}

/// Compare prefixes by cryptographically bound block ID, not by slot count,
/// advertised roots, independently signed peer keys or common state values.
fn common(a:&Chain,b:&Chain)->usize {
    let genesis=a.genesis.id();
    a.blocks.iter().zip(&b.blocks).take_while(|(x,y)|
        x.id(&genesis)==y.id(&genesis)).count()
}
fn same_prefix(short:&Chain,long:&Chain)->bool {
    short.blocks.len()<=long.blocks.len() &&
    common(short,long)==short.blocks.len()
}
fn next_block(history:&Chain,index:usize)->Option<Hash>{
    history.blocks.get(index).map(|b|b.id(&history.genesis.id()))
}
fn anchor(peers:&[PeerView<'_>],immutable:usize)->usize {
    // Already checked that every advertised chain extends the same immutable
    // prefix of the local chain.
    let Some(first)=peers.first() else{return immutable;};
    peers.iter().skip(1).fold(first.history.blocks.len(),|n,p|
        n.min(common(first.history,p.history))).max(immutable)
}
fn density(chain:&Chain,after:usize,start:u64,end:u64)->usize {
    chain.blocks[after..].iter().filter(|block|
        block.slot>start && block.slot<=end).count()
}

/// Source high-level design's *plain, no-CSJ* GDD sufficient conjuncts,
/// simplified by having all headers fully downloaded and cryptographically
/// verified. P/Q must disagree about the immediate successor of the LoE
/// anchor; Q must have >k valid headers beyond the anchor; and Q's visible
/// early-window density must be at least P's maximum possible density.
///
/// A P that explicitly sent AwaitReply promises no currently outstanding
/// headers, so we use its visible density for its temporary upper bound.
/// For Advertising P, all still-unseen later slots are conservatively counted
/// as possibly full. Equality can trigger a disconnect; *that action does
/// NOT by itself choose a canonical chain* or prove a source security theorem.
fn compare(weak:&PeerView<'_>,strong:&PeerView<'_>,
           depth:usize,start:u64,end:u64,k:usize)->Option<GddPair>{
    if weak.id==strong.id ||
       next_block(weak.history,depth)==next_block(strong.history,depth) ||
       strong.history.blocks.len().saturating_sub(depth)<=k {
        return None;
    }
    let weak_count=density(weak.history,depth,start,end);
    let strong_count=density(strong.history,depth,start,end);
    let last=weak.history.blocks.last().map_or(start,|b|b.slot).max(start);
    let still_possible=if weak.header_state==HeaderState::AwaitingReply{
        0
    }else{end.saturating_sub(last) as usize};
    let upper=weak_count.checked_add(still_possible)?;
    if upper>strong_count{return None;}
    Some(GddPair{
        rejected_peer:weak.id,compared_to:strong.id,
        anchor_blocks:depth,anchor_slot:start,end_slot:end,
        weak_density:weak_count,strong_density:strong_count,
        weak_upper_bound:upper,
        strong_after_anchor:strong.history.blocks.len()-depth,
    })
}

/// Read-only finite analogue of LoE and plain GDD. Caller supplies already
/// fully replayed histories and an independently known observation slot.
/// This function does not take a purported current root from any peer.
///
/// `immutable` is the number of locally immutable blocks established under
/// some *separate* legitimate security model. We never manufacture that
/// immutable prefix by looking at the longest/denser advertised candidate.
pub fn trace(local:&Chain,peers:&[PeerView<'_>],
             immutable:usize,observed_slot:u64,mode:GsmMode)
             ->PzResult<SyncTrace>{
    if immutable>local.blocks.len() || peers.len()>128 {
        return Err(Error::Limit);
    }
    let mut seen=BTreeSet::new();
    for peer in peers {
        if !seen.insert(peer.id) {return Err(Error::Duplicate);}
        if peer.history.genesis.id()!=local.genesis.id() ||
           peer.history.blocks.len()<immutable ||
           common(&local,peer.history)<immutable{
            return Err(Error::InvalidBlock);
        }
        if peer.history.blocks.last().is_some_and(|b|b.slot>observed_slot) {
            return Err(Error::InvalidBlock);
        }
    }
    if local.blocks.last().is_some_and(|b|b.slot>observed_slot) {
        return Err(Error::InvalidBlock);
    }
    // No Praos disruption in CaughtUp: LoE and GDD are absent, rather than
    // pretending a density comparison authorizes rollbacks beyond k.
    if mode==GsmMode::CaughtUp {
        return Ok(SyncTrace{mode,connected_peers:peers.len(),
            loe_before:None,loe_after:None,select_ceiling:None,
            gdd_candidates:Vec::new(),proposed_drops:Vec::new(),
            retained_peers:peers.iter().map(|p|p.id).collect(),all_dropped:false});
    }
    // PreSyncing is pinned to the already authenticated immutable prefix,
    // not to a healthy-looking advertised tip or random peer consensus.
    if mode==GsmMode::PreSyncing {
        return Ok(SyncTrace{mode,connected_peers:peers.len(),
            loe_before:Some(immutable),loe_after:Some(immutable),
            select_ceiling:Some(immutable.saturating_add(local.genesis.profile.k_blocks as usize)),
            gdd_candidates:Vec::new(),proposed_drops:Vec::new(),
            retained_peers:peers.iter().map(|p|p.id).collect(),all_dropped:false});
    }
    let loe=anchor(peers,immutable);
    let start=if loe==0{0}else{peers[0].history.blocks[loe-1].slot};
    let end=start.checked_add(local.genesis.profile.s_slots)
        .ok_or(Error::Overflow)?;
    let mut pairs=Vec::new();
    let k=local.genesis.profile.k_blocks as usize;
    for p in peers {
        for q in peers {
            if let Some(detail)=compare(p,q,loe,start,end,k){
                pairs.push(detail);
            }
        }
    }
    let drops:BTreeSet<u16>=pairs.iter().map(|g|g.rejected_peer).collect();
    let remaining:Vec<PeerView<'_>>=peers.iter().copied()
        .filter(|peer|!drops.contains(&peer.id)).collect();
    let after=if remaining.is_empty(){loe}else{anchor(&remaining,immutable)};
    Ok(SyncTrace{
        mode,connected_peers:peers.len(),
        loe_before:Some(loe),loe_after:Some(after),
        select_ceiling:Some(after.saturating_add(k)),
        gdd_candidates:pairs,
        proposed_drops:drops.iter().copied().collect(),
        retained_peers:remaining.iter().map(|p|p.id).collect(),
        all_dropped:!peers.is_empty()&&remaining.is_empty(),
    })
}

/// Limited GSM transition *guard*, NOT the real Cardano GSM. There is no
/// persistent marker, P2P assurance, token-bucket LoP, CSJ or DBF here.
///
/// In this conservative control, being 'caught up' requires (a) an external
/// HAA assumption, (b) all retained peer headers explicitly exhausted, and
/// (c) their histories be prefixes of the selection. The actual Cardano GSM
/// has a subtler candidate-vs-selection predicate and restart hysteresis.
/// A recent-looking block/clock alone is insufficient.
pub fn next_mode(current:GsmMode,haa:HaaEvidence,stale_caught_up:bool,
                 selected:&Chain,views:&[PeerView<'_>],
                 diagnostic:&SyncTrace)->GsmMode{
    match current {
        GsmMode::PreSyncing=>{
            if haa==HaaEvidence::ExternallyAssumed && !views.is_empty() &&
               diagnostic.connected_peers==views.len() {
                GsmMode::Syncing
            }else{GsmMode::PreSyncing}
        }
        GsmMode::Syncing=>{
            if haa==HaaEvidence::Unestablished{
                return GsmMode::PreSyncing;
            }
            if diagnostic.mode!=GsmMode::Syncing ||
               diagnostic.all_dropped || diagnostic.retained_peers.is_empty(){
                return GsmMode::Syncing;
            }
            let current_is_not_worse=views.iter().filter(|p|
                diagnostic.retained_peers.contains(&p.id)).all(|p|
                    p.header_state==HeaderState::AwaitingReply &&
                    same_prefix(p.history,selected));
            if current_is_not_worse{GsmMode::CaughtUp}else{GsmMode::Syncing}
        }
        GsmMode::CaughtUp=>{
            if stale_caught_up{GsmMode::PreSyncing}else{GsmMode::CaughtUp}
        }
    }
}

/// Read-only evidence distinguishing a merely tentative k-block tip fork
/// from a disagreement that reaches INTO a branch's k-deep local prefix.
/// This is a *local comparison*, NOT a proof of common-prefix probability,
/// HAA, honest stake, or a globally canonical settled history.
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct PrefixAgeEvidence {
    pub common_blocks:usize,
    pub left_k_deep_blocks:usize,
    pub right_k_deep_blocks:usize,
    pub left_k_deep_conflict:bool,
    pub right_k_deep_conflict:bool,
}
pub fn prefix_age_evidence(a:&Chain,b:&Chain)->PzResult<PrefixAgeEvidence>{
    if a.genesis.id()!=b.genesis.id(){
        return Err(Error::InvalidBlock);
    }
    let common_blocks=common(a,b);
    let k=a.genesis.profile.k_blocks as usize;
    let left_k_deep_blocks=a.blocks.len().saturating_sub(k);
    let right_k_deep_blocks=b.blocks.len().saturating_sub(k);
    Ok(PrefixAgeEvidence{
        common_blocks,left_k_deep_blocks,right_k_deep_blocks,
        left_k_deep_conflict:common_blocks<left_k_deep_blocks,
        right_k_deep_conflict:common_blocks<right_k_deep_blocks,
    })
}
