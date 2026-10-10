//! Experiment 021: read-only state/density correspondence against genuine
//! PZ-G1 VRF/KES-signed, independently replayed branch histories. This suite
//! MUST NOT replace the original failing 40-OS-process convergence gate.
use algox_phase_zero::pz_g1::{Chain,Genesis,Profile,Prices,Proposer,Error};
use algox_phase_zero::pz_g1::consensus::{prefer_at_slot,Preference};
use algox_phase_zero::pz_g1::genesis_sync_trial::{
    GsmMode,HaaEvidence,HeaderState,PeerView,trace,next_mode,
};
use ed25519_dalek::SigningKey;
use std::collections::BTreeMap;
fn key(b:u8)->SigningKey{SigningKey::from_bytes(&[b;32])}
fn make()->(Genesis,Proposer){
    let owner=key(1);let operator=key(2);
    let proposer=Proposer::from_seeds([51;32],[52;32],
        operator.verifying_key().to_bytes()).unwrap();
    let mut accounts=BTreeMap::new();
    accounts.insert(owner.verifying_key().to_bytes(),1_000_000);
    accounts.insert(operator.verifying_key().to_bytes(),1_000_000);
    let profile=Profile{
        network_salt:[17;32],slot_seconds:1,epoch_slots:8,
        k_blocks:1,s_slots:4,f_num:1,f_den:1,horizon:110,
        issue_base:3,issue_data:2,max_block_events:8,
        max_action_bytes:65_536,max_core_steps:100,max_due_per_block:4,
        max_archive_bytes:65_536,
        prices:Prices{per_byte:1,per_signature:1,per_core_step:0,
            per_state_byte:0,per_proof:0,per_terminal:2},
        core_digest:[7;32],runtime_digest:[8;32],
    };
    (Genesis{activation_unix_ms:None,profile,accounts,
        locked:vec![proposer.credential(owner.verifying_key().to_bytes(),20,5000)]},
     proposer)
}
fn more()->Proposer{Proposer::from_seeds([51;32],[52;32],
    key(2).verifying_key().to_bytes()).unwrap()}
fn step(c:&mut Chain,p:&mut Proposer,slot:u64){
    c.produce(p,slot,vec![],true).unwrap();
}
fn branches()->(Genesis,Chain,Chain,Chain){
    let (g,mut p)=make();
    let mut root=Chain::new(g.clone()).unwrap();step(&mut root,&mut p,1);
    let mut dense=root.clone();let mut sparse=root.clone();
    let mut d=more();let mut s=more();
    for slot in [2,3,4,5,6]{step(&mut dense,&mut d,slot);}
    for slot in [6,8,9,10]{step(&mut sparse,&mut s,slot);}
    let d=Chain::replay(g.clone(),&dense.blocks).unwrap();
    let s=Chain::replay(g.clone(),&sparse.blocks).unwrap();
    (g,root,d,s)
}
#[test]
fn mode_pre_sync_keeps_immutable_anchor_and_requires_external_haa(){
    let (_,root,dense,sparse)=branches();
    let views=[
        PeerView{id:1,history:&dense,header_state:HeaderState::Advertising},
        PeerView{id:2,history:&sparse,header_state:HeaderState::AwaitingReply},
    ];
    let a=trace(&dense,&views,root.blocks.len(),50,GsmMode::PreSyncing).unwrap();
    assert_eq!(a.loe_before,Some(1));
    assert_eq!(a.loe_after,Some(1));
    assert_eq!(a.select_ceiling,Some(2));
    assert!(a.gdd_candidates.is_empty());
    assert_eq!(next_mode(GsmMode::PreSyncing,HaaEvidence::Unestablished,
        false,&dense,&views,&a),GsmMode::PreSyncing);
    assert_eq!(next_mode(GsmMode::PreSyncing,HaaEvidence::ExternallyAssumed,
        false,&dense,&views,&a),GsmMode::Syncing);
    assert_eq!(next_mode(GsmMode::PreSyncing,HaaEvidence::ExternallyAssumed,
        false,&dense,&[],&a),GsmMode::PreSyncing);
}
#[test]
fn one_sparse_awaiting_peer_can_be_flagged_and_loe_can_advance(){
    let (_,root,dense,sparse)=branches();
    let peers=[
        PeerView{id:1,history:&dense,header_state:HeaderState::Advertising},
        PeerView{id:2,history:&sparse,header_state:HeaderState::AwaitingReply},
    ];
    let x=trace(&dense,&peers,root.blocks.len(),50,GsmMode::Syncing).unwrap();
    assert_eq!(x.loe_before,Some(1));
    assert_eq!(x.proposed_drops,vec![2]);
    assert_eq!(x.retained_peers,vec![1]);
    assert_eq!(x.loe_after,Some(dense.blocks.len()));
    assert_eq!(x.select_ceiling,Some(dense.blocks.len()+1));
    assert!(!x.all_dropped);
    let d=&x.gdd_candidates[0];
    assert_eq!((d.anchor_slot,d.end_slot,d.weak_density,d.strong_density),
               (1,5,0,4));
    // Proposed *peer* disconnection does not select or mutate economic state.
    assert_eq!(sparse.blocks.len(),5);
}
#[test]
fn possible_future_headers_block_premature_disconnection(){
    let (g,root,_,_)=branches();
    // Distinct first successors after slot 1. The strong branch has only
    // two blocks in (1,5], so the incomplete advertising weak branch could
    // still surpass it if future headers fill every later window slot.
    let mut strong=root.clone();let mut q=more();
    for slot in [3,5,6,7]{step(&mut strong,&mut q,slot);}
    let strong=Chain::replay(g.clone(),&strong.blocks).unwrap();
    let mut weak=root.clone();let mut p=more();step(&mut weak,&mut p,2);
    let weak=Chain::replay(g,&weak.blocks).unwrap();
    let mut views=[
        PeerView{id:1,history:&strong,header_state:HeaderState::Advertising},
        PeerView{id:2,history:&weak,header_state:HeaderState::Advertising},
    ];
    let x=trace(&strong,&views,1,50,GsmMode::Syncing).unwrap();
    assert!(x.proposed_drops.is_empty());
    // Last weak slot=2 and window ends at 5, so maximum possible weak
    // density is 1+3=4, versus the strong currently visible density 2.
    // The first red test wrongly used a fully occupied strong window, whose
    // density of 4 could not be strictly surpassed even by filling all
    // remaining weak slots. Equality legitimately satisfies the GDD bound.
    views[1].header_state=HeaderState::AwaitingReply;
    let y=trace(&strong,&views,1,50,GsmMode::Syncing).unwrap();
    assert_eq!(y.proposed_drops,vec![2]);
}
#[test]
fn empty_early_window_mutual_keep_is_not_solved_by_naive_gdd(){
    let (g,root,_,_)=branches();
    let mut a=root.clone();let mut b=root.clone();
    let mut p=more();let mut q=more();
    for slot in [6,8,9,10]{step(&mut a,&mut p,slot);}
    for slot in [7,9,11]{step(&mut b,&mut q,slot);}
    let a=Chain::replay(g.clone(),&a.blocks).unwrap();
    let b=Chain::replay(g,&b.blocks).unwrap();
    assert_eq!(prefer_at_slot(&a,&b,50),Ok(Preference::Keep));
    assert_eq!(prefer_at_slot(&b,&a,50),Ok(Preference::Keep));
    let views=[
        PeerView{id:10,history:&a,header_state:HeaderState::AwaitingReply},
        PeerView{id:20,history:&b,header_state:HeaderState::AwaitingReply},
    ];
    let x=trace(&a,&views,1,50,GsmMode::Syncing).unwrap();
    assert_eq!(x.proposed_drops,vec![10,20]);
    assert!(x.all_dropped); // No honest chain-growth guarantee was established.
    assert_eq!(x.loe_after,Some(1));
    assert_eq!(x.gdd_candidates.len(),2);
    assert!(x.gdd_candidates.iter().all(|w|
        w.weak_density==0 && w.strong_density==0 &&
        w.strong_after_anchor>1));
    assert_eq!(next_mode(GsmMode::Syncing,HaaEvidence::ExternallyAssumed,
        false,&a,&views,&x),GsmMode::Syncing);
    assert_eq!(next_mode(GsmMode::Syncing,HaaEvidence::Unestablished,
        false,&a,&views,&x),GsmMode::PreSyncing);
}
#[test]
fn equally_dense_nonempty_early_forks_remain_undecidable_under_lab_profile(){
    // A real 40-OS-process run (38027730636) independently replayed 40/40
    // original-genesis archives, but two distinct branches had density 2-2
    // in the first four slots after the intersection. Reproduce the same
    // *shape* independently with actual VRF/KES-signed, valid branches.
    let (g,root,_,_)=branches();
    let mut a=root.clone();let mut b=root.clone();
    let mut p=more();let mut q=more();
    for slot in [2,4,6,8,9]{step(&mut a,&mut p,slot);}
    for slot in [3,5,7,10]{step(&mut b,&mut q,slot);}
    let a=Chain::replay(g.clone(),&a.blocks).unwrap();
    let b=Chain::replay(g,&b.blocks).unwrap();
    assert_ne!(a.tip(),b.tip());
    assert_eq!(prefer_at_slot(&a,&b,50),Ok(Preference::Keep));
    assert_eq!(prefer_at_slot(&b,&a,50),Ok(Preference::Keep));
    for header_state in [HeaderState::Advertising,HeaderState::AwaitingReply]{
        let peers=[
            PeerView{id:10,history:&a,header_state},
            PeerView{id:20,history:&b,header_state},
        ];
        let x=trace(&a,&peers,1,50,GsmMode::Syncing).unwrap();
        assert_eq!(x.loe_before,Some(1));
        assert_eq!(x.gdd_candidates.len(),2);
        assert_eq!(x.proposed_drops,vec![10,20]);
        assert!(x.all_dropped);
        assert!(x.gdd_candidates.iter().all(|d|
            d.anchor_slot==1 && d.end_slot==5 &&
            d.weak_density==2 && d.strong_density==2 &&
            d.weak_upper_bound==2 && d.strong_after_anchor>1));
    }
    // Neither a taller total branch nor a second signed vote from another
    // peer establishes a canonical economic history.
}

#[test]
fn caught_up_mode_disables_loe_gdd_and_staleness_restarts_syncing(){
    let (_,root,dense,sparse)=branches();
    let peers=[
        PeerView{id:1,history:&dense,header_state:HeaderState::Advertising},
        PeerView{id:2,history:&sparse,header_state:HeaderState::AwaitingReply},
    ];
    let x=trace(&dense,&peers,root.blocks.len(),50,GsmMode::CaughtUp).unwrap();
    assert_eq!(x.loe_before,None);
    assert_eq!(x.select_ceiling,None);
    assert!(x.gdd_candidates.is_empty());
    assert_eq!(next_mode(GsmMode::CaughtUp,HaaEvidence::Unestablished,
        false,&dense,&peers,&x),GsmMode::CaughtUp);
    assert_eq!(next_mode(GsmMode::CaughtUp,HaaEvidence::ExternallyAssumed,
        true,&dense,&peers,&x),GsmMode::PreSyncing);
}
#[test]
fn syncing_caught_up_requires_exhausted_compatible_peers_not_new_tip_time(){
    let (_,root,dense,sparse)=branches();
    let mut a=[PeerView{id:1,history:&dense,
        header_state:HeaderState::Advertising}];
    let pending=trace(&dense,&a,root.blocks.len(),50,GsmMode::Syncing).unwrap();
    assert_eq!(next_mode(GsmMode::Syncing,HaaEvidence::ExternallyAssumed,
        false,&dense,&a,&pending),GsmMode::Syncing);
    a[0].header_state=HeaderState::AwaitingReply;
    let done=trace(&dense,&a,root.blocks.len(),50,GsmMode::Syncing).unwrap();
    assert_eq!(next_mode(GsmMode::Syncing,HaaEvidence::ExternallyAssumed,
        false,&dense,&a,&done),GsmMode::CaughtUp);
    let diverged=[PeerView{id:2,history:&sparse,
        header_state:HeaderState::AwaitingReply}];
    let notdone=trace(&dense,&diverged,1,50,GsmMode::Syncing).unwrap();
    assert_eq!(next_mode(GsmMode::Syncing,HaaEvidence::ExternallyAssumed,
        false,&dense,&diverged,&notdone),GsmMode::Syncing);
}
#[test]
fn invalid_immutable_conflicts_future_headers_duplicates_and_foreign_genesis_fail(){
    let (g,_,dense,sparse)=branches();
    let peers=[PeerView{id:1,history:&sparse,header_state:HeaderState::Advertising}];
    assert_eq!(trace(&dense,&peers,2,50,GsmMode::Syncing).err(),Some(Error::InvalidBlock));
    assert_eq!(trace(&dense,&peers,1,5,GsmMode::Syncing).err(),Some(Error::InvalidBlock));
    let duplicate=[
        PeerView{id:7,history:&dense,header_state:HeaderState::Advertising},
        PeerView{id:7,history:&dense,header_state:HeaderState::AwaitingReply},
    ];
    assert_eq!(trace(&dense,&duplicate,1,50,GsmMode::Syncing).err(),
        Some(Error::Duplicate));
    let mut alien=g;alien.profile.network_salt=[99;32];
    let foreign=Chain::new(alien).unwrap();
    let different=[PeerView{id:2,history:&foreign,header_state:HeaderState::AwaitingReply}];
    assert_eq!(trace(&dense,&different,0,50,GsmMode::Syncing).err(),
        Some(Error::InvalidBlock));
    assert_eq!(trace(&dense,&[],200,50,GsmMode::Syncing).err(),Some(Error::Limit));
}
#[test]
fn several_matching_signatures_cannot_establish_haa(){
    let (_,root,dense,_)=branches();
    let peers=[
        PeerView{id:1,history:&dense,header_state:HeaderState::AwaitingReply},
        PeerView{id:2,history:&dense,header_state:HeaderState::AwaitingReply},
        PeerView{id:3,history:&dense,header_state:HeaderState::AwaitingReply},
    ];
    let r=trace(&dense,&peers,root.blocks.len(),50,GsmMode::Syncing).unwrap();
    assert_eq!(r.loe_before,Some(dense.blocks.len()));
    assert!(r.gdd_candidates.is_empty());
    assert_eq!(next_mode(GsmMode::Syncing,HaaEvidence::Unestablished,
        false,&dense,&peers,&r),GsmMode::PreSyncing);
}

#[test]
fn read_only_k_depth_diagnostic_distinguishes_tentative_tips_from_deep_disagreement(){
    use algox_phase_zero::pz_g1::genesis_sync_trial::prefix_age_evidence;
    let (g,mut original)=make();
    let mut common=Chain::new(g.clone()).unwrap();
    for slot in [1,2,3,4] {step(&mut common,&mut original,slot);}
    let mut left=common.clone();let mut right=common.clone();
    let mut p=more();let mut q=more();
    step(&mut left,&mut p,5);step(&mut right,&mut q,6);
    let left=Chain::replay(g.clone(),&left.blocks).unwrap();
    let right=Chain::replay(g.clone(),&right.blocks).unwrap();
    let shallow=prefix_age_evidence(&left,&right).unwrap();
    assert_eq!(shallow.common_blocks,4);
    assert_eq!(shallow.left_k_deep_blocks,4);
    assert_eq!(shallow.right_k_deep_blocks,4);
    assert!(!shallow.left_k_deep_conflict);
    assert!(!shallow.right_k_deep_conflict);

    let mut root=Chain::new(g.clone()).unwrap();
    let mut one=more();step(&mut root,&mut one,1);
    let mut a=root.clone();let mut b=root.clone();
    let mut sa=more();let mut sb=more();
    for slot in [6,8,9,10] {step(&mut a,&mut sa,slot);}
    for slot in [7,9,11] {step(&mut b,&mut sb,slot);}
    let a=Chain::replay(g.clone(),&a.blocks).unwrap();
    let b=Chain::replay(g,&b.blocks).unwrap();
    let deep=prefix_age_evidence(&a,&b).unwrap();
    assert_eq!(deep.common_blocks,1);
    assert!(deep.left_k_deep_conflict);
    assert!(deep.right_k_deep_conflict);
    assert_eq!(deep.left_k_deep_blocks,4);
    assert_eq!(deep.right_k_deep_blocks,3);
}
