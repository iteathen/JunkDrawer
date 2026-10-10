//! Experiment 023 — bounded event-driven source-component research over
//! genuinely VRF/KES-produced, separately original-genesis-replayed histories.
//! No test constructs a winning consensus root or mutates live fork choice.
use algox_phase_zero::pz_g1::{Chain,Genesis,Profile,Prices,Proposer,Error};
use algox_phase_zero::pz_g1::chain_sync_observe::{respond,Reply,Observed};
use algox_phase_zero::pz_g1::genesis_sync_trial::GsmMode;
use algox_phase_zero::pz_g1::genesis_event_trial::{EventDriven,Parameters,Reason};
use ed25519_dalek::SigningKey;
use std::collections::BTreeMap;

fn key(b:u8)->SigningKey {SigningKey::from_bytes(&[b;32])}
fn proposer()->Proposer {
    Proposer::from_seeds([51;32],[52;32],key(2).verifying_key().to_bytes()).unwrap()
}
fn fixture()->Genesis {
    let owner=key(1);let operator=key(2);let signing=proposer();
    let mut accounts=BTreeMap::new();
    accounts.insert(owner.verifying_key().to_bytes(),1_000_000);
    accounts.insert(operator.verifying_key().to_bytes(),1_000_000);
    Genesis{
        activation_unix_ms:None,
        profile:Profile{
            network_salt:[17;32],slot_seconds:1,epoch_slots:8,
            k_blocks:1,s_slots:4,f_num:1,f_den:1,horizon:110,
            issue_base:3,issue_data:2,max_block_events:8,
            max_action_bytes:65_536,max_core_steps:100,max_due_per_block:4,
            max_archive_bytes:65_536,
            prices:Prices{per_byte:1,per_signature:1,per_core_step:0,
                per_state_byte:0,per_proof:0,per_terminal:2},
            core_digest:[7;32],runtime_digest:[8;32],
        },
        accounts,
        locked:vec![signing.credential(owner.verifying_key().to_bytes(),20,5000)],
    }
}
fn step(c:&mut Chain,p:&mut Proposer,slot:u64) {
    c.produce(p,slot,vec![],true).unwrap();
}
fn roots()->(Genesis,Chain,Chain,Chain){
    let g=fixture();
    let mut shared=Chain::new(g.clone()).unwrap();
    step(&mut shared,&mut proposer(),1);
    let mut honest=shared.clone();let mut weak=shared.clone();
    let mut a=proposer();let mut b=proposer();
    for slot in [2,3,4,5,6]{step(&mut honest,&mut a,slot);}
    for slot in [6,8,9,10]{step(&mut weak,&mut b,slot);}
    let honest=Chain::replay(g.clone(),&honest.blocks).unwrap();
    let weak=Chain::replay(g.clone(),&weak.blocks).unwrap();
    (g,shared,honest,weak)
}
fn tie()->(Genesis,Chain,Chain,Chain){
    let g=fixture();
    let mut shared=Chain::new(g.clone()).unwrap();
    step(&mut shared,&mut proposer(),1);
    let mut a=shared.clone();let mut b=shared.clone();
    let mut pa=proposer();let mut pb=proposer();
    for slot in [2,4,6,8,9]{step(&mut a,&mut pa,slot);}
    for slot in [3,5,7,10]{step(&mut b,&mut pb,slot);}
    let a=Chain::replay(g.clone(),&a.blocks).unwrap();
    let b=Chain::replay(g.clone(),&b.blocks).unwrap();
    (g,shared,a,b)
}
fn config()->Parameters {
    Parameters{gdd_cooldown_ms:100,patience_capacity_ms:20_000,
        max_assumed_rtt_ms:1000,patience_refill_ms:100,
        ..Parameters::finite_control()}
}
/// Exchange real header wire replies and then separately replay a full
/// original-genesis economic chain; the chosen time model is test-only.
fn feed(lab:&mut EventDriven,id:u16,source:&Chain,clock:&mut u64){
    for _ in &source.blocks {
        let q=lab.begin_poll(id).unwrap();
        let reply=respond(source,&q).unwrap();
        *clock+=10;
        assert_eq!(lab.observe(id,reply,*clock,50),Ok(Observed::Forward));
    }
    let q=lab.begin_poll(id).unwrap();
    let reply=respond(source,&q).unwrap();
    *clock+=10;
    assert_eq!(lab.observe(id,reply,*clock,50),Ok(Observed::Await));
    lab.correlate_full_history(id,source).unwrap();
}
#[test]
fn qualified_honest_early_density_allows_one_lab_gdd_drop_and_loe_progress(){
    let (_g,_,honest,weak)=roots();
    let mut lab=EventDriven::new(&honest,1,config()).unwrap();
    lab.connect(10).unwrap();lab.connect(20).unwrap();
    lab.assume_honest_upstream(10).unwrap();
    assert_eq!(lab.mode,GsmMode::Syncing);
    let mut clock=0;
    feed(&mut lab,10,&honest,&mut clock);
    feed(&mut lab,20,&weak,&mut clock);
    let before=lab.snapshot().unwrap();
    assert_eq!(before.honest_source_assumed,Some(10));
    assert_eq!(before.honest_growth_and_dominance,Some(true));
    assert_eq!(before.proposed_gdd_drops,vec![20]);
    assert!(!before.drops_unsafe_or_unresolved);
    assert_eq!(before.source_trial.unwrap().loe_before,Some(1));
    lab.disconnect_one_gdd(20).unwrap();
    let after=lab.snapshot().unwrap();
    assert_eq!(after.active_peers,vec![10]);
    assert_eq!(lab.mode,GsmMode::CaughtUp);
    // Does NOT select 'honest': the node was already externally given a
    // separately original-genesis-verified local chain.
    assert!(lab.records().iter().any(|x|x.why==Reason::GddDisconnected));
}
#[test]
fn equal_nonzero_density_flags_both_peers_and_refuses_unsafe_disconnect(){
    let (_,_,a,b)=tie();
    let mut lab=EventDriven::new(&a,1,config()).unwrap();
    lab.connect(10).unwrap();lab.connect(20).unwrap();
    lab.assume_honest_upstream(10).unwrap();
    let mut clock=0;
    feed(&mut lab,10,&a,&mut clock);
    feed(&mut lab,20,&b,&mut clock);
    let s=lab.snapshot().unwrap();
    assert_eq!(s.proposed_gdd_drops,vec![10,20]);
    assert!(s.drops_unsafe_or_unresolved);
    assert_eq!(s.honest_growth_and_dominance,Some(false));
    assert_eq!(lab.disconnect_one_gdd(20),Err(Error::Unavailable));
    assert_eq!(lab.snapshot().unwrap().active_peers,vec![10,20]);
    assert_eq!(lab.mode,GsmMode::Syncing);
}
#[test]
fn signatures_and_awaits_do_not_establish_haa_or_caught_up(){
    let (_,_,honest,_)=roots();
    let mut lab=EventDriven::new(&honest,1,config()).unwrap();
    lab.connect(10).unwrap();lab.connect(20).unwrap();
    let mut clock=0;
    feed(&mut lab,10,&honest,&mut clock);
    feed(&mut lab,20,&honest,&mut clock);
    assert_eq!(lab.mode,GsmMode::PreSyncing);
    assert!(!lab.snapshot().unwrap().honest_source_available);
    lab.assume_honest_upstream(10).unwrap();
    assert_eq!(lab.mode,GsmMode::Syncing);
    lab.advance(clock+1,50).unwrap();
    assert_eq!(lab.mode,GsmMode::CaughtUp);
    lab.withdraw_haa().unwrap();
    assert_eq!(lab.mode,GsmMode::CaughtUp); // No Praos disruption
    lab.mark_caught_up_stale().unwrap();
    assert_eq!(lab.mode,GsmMode::PreSyncing);
}
#[test]
fn unreplayed_headers_and_delay_bound_break_conditional_evidence(){
    let (_,_,honest,weak)=roots();
    let mut conf=config();conf.max_assumed_rtt_ms=20;
    let mut lab=EventDriven::new(&honest,1,conf).unwrap();
    lab.connect(1).unwrap();lab.connect(2).unwrap();
    lab.assume_honest_upstream(1).unwrap();
    let q=lab.begin_poll(1).unwrap();
    let reply=respond(&honest,&q).unwrap();
    assert_eq!(lab.observe(1,reply,50,50),Ok(Observed::Forward));
    assert_eq!(lab.snapshot().unwrap().assumed_latency_violations,1);
    assert!(lab.snapshot().unwrap().source_trial.is_none());
    assert_eq!(lab.snapshot().unwrap().pending_economic_replay,vec![1,2]);
    let prefix=Chain::replay(honest.genesis.clone(),&honest.blocks[..1]).unwrap();
    lab.correlate_full_history(1,&prefix).unwrap();
    let bad=lab.correlate_full_history(2,&weak);
    assert_eq!(bad,Err(Error::InvalidProof));
    // A later header invalidates a previously replay-confirmed prefix.
    let q2=lab.begin_poll(1).unwrap();
    let r2=respond(&honest,&q2).unwrap();
    assert_eq!(lab.observe(1,r2,60,50),Ok(Observed::Forward));
    assert!(lab.snapshot().unwrap().pending_economic_replay.contains(&1));
    // External HAA timing premise failed in this controlled scenario.
    assert_eq!(lab.mode,GsmMode::PreSyncing);
}
#[test]
fn patience_leaks_for_unresponsive_header_promises_but_pauses_on_await_and_forecast(){
    let (_,_,honest,_)=roots();
    let mut conf=config();conf.patience_capacity_ms=300;
    let mut lab=EventDriven::new(&honest,1,conf).unwrap();
    lab.connect(1).unwrap();lab.connect(2).unwrap();lab.connect(3).unwrap();
    lab.assume_honest_upstream(1).unwrap();
    let empty=Chain::new(honest.genesis.clone()).unwrap();
    let q=lab.begin_poll(1).unwrap();
    let reply=respond(&empty,&q).unwrap();
    assert_eq!(lab.observe(1,reply,10,10),Ok(Observed::Await));
    lab.mark_outside_forecast(3,true).unwrap();
    lab.advance(250,10).unwrap();
    assert_eq!(lab.snapshot().unwrap().active_peers,vec![1,2,3]);
    lab.advance(400,10).unwrap();
    assert_eq!(lab.snapshot().unwrap().active_peers,vec![1,3]);
    assert!(lab.records().iter().any(|x|x.id==Some(2) &&
        x.why==Reason::PatienceExpired));
    lab.mark_outside_forecast(3,false).unwrap();
    lab.advance(720,10).unwrap();
    assert_eq!(lab.snapshot().unwrap().active_peers,vec![1]);
    assert!(lab.snapshot().unwrap().honest_source_available);
    // No HAA can be proved by this. 'Honest' is an explicit lab label.
    assert_eq!(lab.mode,GsmMode::Syncing);
}
#[test]
fn losing_assumed_honest_upstream_disables_sync_without_root_invention(){
    let (_,_,honest,_)=roots();
    let mut conf=config();conf.patience_capacity_ms=100;
    let mut lab=EventDriven::new(&honest,1,conf).unwrap();
    lab.connect(1).unwrap();lab.assume_honest_upstream(1).unwrap();
    assert_eq!(lab.mode,GsmMode::Syncing);
    lab.advance(150,20).unwrap();
    assert_eq!(lab.snapshot().unwrap().active_peers,Vec::<u16>::new());
    assert!(!lab.snapshot().unwrap().honest_source_available);
    assert_eq!(lab.mode,GsmMode::PreSyncing);
    assert_eq!(lab.disconnect_one_gdd(1),Err(Error::Unavailable));
}
#[test]
fn only_original_genesis_replayed_bytes_corroborate_wire_state(){
    let (_,_,honest,weak)=roots();
    let mut lab=EventDriven::new(&honest,1,config()).unwrap();
    lab.connect(10).unwrap();lab.assume_honest_upstream(10).unwrap();
    let q=lab.begin_poll(10).unwrap();
    let reply=respond(&honest,&q).unwrap();
    assert_eq!(lab.observe(10,reply,10,50),Ok(Observed::Forward));
    assert_eq!(lab.correlate_full_history(10,&weak),Err(Error::InvalidProof));
    let prefix=Chain::replay(honest.genesis.clone(),&honest.blocks[..1]).unwrap();
    lab.correlate_full_history(10,&prefix).unwrap();
    assert_eq!(lab.snapshot().unwrap().pending_economic_replay.len(),0);
    let forged=Reply::AwaitReply{height:5,tip:[99;32]};
    let _poll=lab.begin_poll(10).unwrap();
    assert_eq!(lab.observe(10,forged,20,50),Err(Error::InvalidProof));
    assert_eq!(lab.snapshot().unwrap().observed_headers[0].1,1);
}
#[test]
fn gdd_cooldown_separates_disconnections_and_reevaluates_loe(){
    let (_,_,honest,weak)=roots();
    let mut lab=EventDriven::new(&honest,1,config()).unwrap();
    lab.connect(10).unwrap();lab.connect(20).unwrap();lab.connect(21).unwrap();
    lab.assume_honest_upstream(10).unwrap();
    let mut clock=0;
    feed(&mut lab,10,&honest,&mut clock);
    feed(&mut lab,20,&weak,&mut clock);
    feed(&mut lab,21,&weak,&mut clock);
    let s=lab.snapshot().unwrap();
    assert_eq!(s.proposed_gdd_drops,vec![20,21]);
    lab.disconnect_one_gdd(20).unwrap();
    assert_eq!(lab.disconnect_one_gdd(21),Err(Error::Unavailable));
    lab.advance(clock+101,50).unwrap();
    lab.disconnect_one_gdd(21).unwrap();
    assert_eq!(lab.snapshot().unwrap().active_peers,vec![10]);
    assert_eq!(lab.mode,GsmMode::CaughtUp);
}

#[test]
fn violated_assumed_honest_poll_latency_prevents_claimed_safe_gdd_progress(){
    let (_,_,honest,weak)=roots();
    let mut conf=config();
    conf.max_assumed_rtt_ms=5; // explicit research bound, not source Delta
    let mut lab=EventDriven::new(&honest,1,conf).unwrap();
    lab.connect(10).unwrap();lab.connect(20).unwrap();
    lab.assume_honest_upstream(10).unwrap();
    let mut clock=0;
    feed(&mut lab,10,&honest,&mut clock); // each real signed-header poll >5 ms
    feed(&mut lab,20,&weak,&mut clock);
    let snapshot=lab.snapshot().unwrap();
    assert_eq!(snapshot.honest_growth_and_dominance,Some(true));
    // Relative density remains true, but the test-world timing premise
    // failed: PreSyncing must not even propose GDD disconnections.
    assert!(snapshot.proposed_gdd_drops.is_empty());
    assert!(snapshot.honest_poll_bound_breached);
    assert!(snapshot.assumed_latency_violations>0);
    assert!(!snapshot.honest_source_available);
    assert_eq!(lab.disconnect_one_gdd(20),Err(Error::Unavailable));
    assert_eq!(lab.snapshot().unwrap().active_peers,vec![10,20]);
    assert_eq!(lab.mode,GsmMode::PreSyncing);
}

#[test]
fn stale_await_reply_requires_new_observed_header_exhaustion(){
    let (_,_,honest,_)=roots();
    let mut conf=config();
    conf.max_await_age_ms=20; // explicit lab freshness, not canonical time
    let mut lab=EventDriven::new(&honest,1,conf).unwrap();
    lab.connect(10).unwrap();
    lab.connect(20).unwrap();
    let mut now=0;
    feed(&mut lab,10,&honest,&mut now);
    feed(&mut lab,20,&honest,&mut now);
    lab.assume_honest_upstream(10).unwrap();
    lab.advance(now+1,50).unwrap();
    assert_eq!(lab.mode,GsmMode::Syncing);
    // Despite two valid identical signed histories, an old AwaitReply no
    // longer certifies that every peer is simultaneously finished.
    let q=lab.begin_poll(10).unwrap();
    let msg=respond(&honest,&q).unwrap();
    now+=2;
    assert_eq!(lab.observe(10,msg,now,50),Ok(Observed::RepeatedAwait));
    assert_eq!(lab.mode,GsmMode::CaughtUp);
}

#[test]
fn separately_valid_peer_cannot_override_external_immutable_anchor(){
    let (g,_,honest,_)=roots();
    // Both are genuinely VRF/KES-signed and fully replayable, but their
    // *first* block differs: one valid branch is not a successor of the
    // independently supplied immutable prefix of the local selection.
    let mut rival=Chain::new(g.clone()).unwrap();
    let mut p=proposer();
    step(&mut rival,&mut p,2);
    let rival=Chain::replay(g,&rival.blocks).unwrap();
    let mut lab=EventDriven::new(&honest,1,config()).unwrap();
    lab.connect(10).unwrap();
    lab.assume_honest_upstream(10).unwrap();
    let request=lab.begin_poll(10).unwrap();
    let reply=respond(&rival,&request).unwrap();
    assert_eq!(lab.observe(10,reply,10,50),Ok(Observed::Forward));
    assert_eq!(lab.correlate_full_history(10,&rival),Err(Error::InvalidBlock));
    assert_eq!(lab.snapshot().unwrap().pending_economic_replay,vec![10]);
    let local_prefix=Chain::replay(honest.genesis.clone(),
        &honest.blocks[..1]).unwrap();
    assert_eq!(lab.correlate_full_history(10,&local_prefix),Err(Error::InvalidProof));
    assert_eq!(lab.mode,GsmMode::Syncing); // No selected root was replaced.
}

#[test]
fn rejoining_peer_id_needs_a_new_external_honest_availability_assumption(){
    let (_,_,honest,_)=roots();
    let mut p=config();
    p.patience_capacity_ms=100;
    let mut lab=EventDriven::new(&honest,1,p).unwrap();
    lab.connect(10).unwrap();
    lab.assume_honest_upstream(10).unwrap();
    assert_eq!(lab.mode,GsmMode::Syncing);
    lab.advance(150,20).unwrap(); // no promised header delivered
    assert_eq!(lab.mode,GsmMode::PreSyncing);
    assert_eq!(lab.snapshot().unwrap().honest_source_assumed,None);
    lab.connect(10).unwrap(); // same test key, *new* actual connection
    assert!(!lab.snapshot().unwrap().honest_source_available);
    assert_eq!(lab.mode,GsmMode::PreSyncing);
    lab.assume_honest_upstream(10).unwrap();
    assert_eq!(lab.mode,GsmMode::Syncing);
}

#[test]
fn proposed_gdd_drops_do_not_implicitly_change_sync_state_or_remove_peers(){
    let (_,_,honest,weak)=roots();
    let mut lab=EventDriven::new(&honest,1,config()).unwrap();
    lab.connect(10).unwrap();lab.connect(20).unwrap();
    lab.assume_honest_upstream(10).unwrap();
    let mut clock=0;
    feed(&mut lab,10,&honest,&mut clock);
    assert_eq!(lab.mode,GsmMode::Syncing);
    feed(&mut lab,20,&weak,&mut clock);
    let candidate=lab.snapshot().unwrap();
    assert_eq!(candidate.mode,GsmMode::Syncing);
    assert_eq!(candidate.proposed_gdd_drops,vec![20]);
    assert_eq!(candidate.active_peers,vec![10,20]);
    assert_eq!(candidate.source_trial.unwrap().mode,GsmMode::Syncing);
    assert!(!lab.records().iter().any(|r|r.why==Reason::GddDisconnected));
    // A *separate*, guarded act of removing an actual peer must precede
    // concluding that the remaining verified source is caught up.
    lab.disconnect_one_gdd(20).unwrap();
    assert_eq!(lab.snapshot().unwrap().active_peers,vec![10]);
    assert_eq!(lab.mode,GsmMode::CaughtUp);
}

#[test]
fn prefixed_peer_does_not_justify_gdd_when_assumed_honest_chain_has_zero_early_growth(){
    // Legitimately VRF/KES-produced and independently replayed histories:
    // the test-labelled honest chain grows *only after* the four-slot
    // source-density window. The other peer is a valid older PREFIX.
    //
    // The original lab's dominance predicate skipped prefix peers entirely,
    // which would label absent early honest growth as justified GDD safety.
    let (_,old_prefix,_,late)=roots();
    let mut lab=EventDriven::new(&late,1,config()).unwrap();
    lab.connect(10).unwrap();
    lab.connect(20).unwrap();
    lab.assume_honest_upstream(10).unwrap();
    let mut clock=0;
    feed(&mut lab,10,&late,&mut clock);
    feed(&mut lab,20,&old_prefix,&mut clock);
    let snapshot=lab.snapshot().unwrap();
    assert_eq!(snapshot.mode,GsmMode::Syncing);
    assert_eq!(snapshot.proposed_gdd_drops,vec![20]);
    assert_eq!(snapshot.honest_growth_and_dominance,Some(false),
        "a mere prefix peer cannot waive the honest chain-growth premise");
    assert_eq!(lab.disconnect_one_gdd(20),Err(Error::Unavailable));
    assert_eq!(lab.snapshot().unwrap().active_peers,vec![10,20]);
}

#[test]
fn prefixed_peer_does_not_justify_gdd_when_early_growth_is_at_most_k(){
    let (g,prefix,_,_)=roots();
    let mut partly_grown=prefix.clone();
    let mut signer=proposer();
    // Relative to last shared block at slot 1, the s=4 window contains
    // *one* honest block at slot 2: not strictly more than k=1.
    for slot in [2,7,8,9] {
        step(&mut partly_grown,&mut signer,slot);
    }
    let partly_grown=Chain::replay(g,&partly_grown.blocks).unwrap();
    let mut lab=EventDriven::new(&partly_grown,1,config()).unwrap();
    lab.connect(10).unwrap();
    lab.connect(20).unwrap();
    lab.assume_honest_upstream(10).unwrap();
    let mut clock=0;
    feed(&mut lab,10,&partly_grown,&mut clock);
    feed(&mut lab,20,&prefix,&mut clock);
    let snapshot=lab.snapshot().unwrap();
    assert_eq!(snapshot.mode,GsmMode::Syncing);
    assert_eq!(snapshot.proposed_gdd_drops,vec![20]);
    assert_eq!(snapshot.honest_growth_and_dominance,Some(false));
    assert_eq!(lab.disconnect_one_gdd(20),Err(Error::Unavailable));
    assert!(!lab.records().iter().any(|x|x.why==Reason::GddDisconnected));
}

#[test]
fn properly_grown_honest_chain_can_exclude_a_lagging_proper_prefix_conditionally(){
    // Positive control for the two prefix-growth regressions: the assumed
    // honest history has four genuinely signed early-window blocks >k=1.
    // A full, independently replayed older prefix is not allowed to stall
    // the lab indefinitely *when* that conditional density premise holds.
    let (_,prefix,honest,_)=roots();
    let mut lab=EventDriven::new(&honest,1,config()).unwrap();
    lab.connect(10).unwrap();
    lab.connect(20).unwrap();
    lab.assume_honest_upstream(10).unwrap();
    let mut time=0;
    feed(&mut lab,10,&honest,&mut time);
    feed(&mut lab,20,&prefix,&mut time);
    let state=lab.snapshot().unwrap();
    assert_eq!(state.mode,GsmMode::Syncing);
    assert_eq!(state.proposed_gdd_drops,vec![20]);
    assert_eq!(state.honest_growth_and_dominance,Some(true));
    lab.disconnect_one_gdd(20).unwrap();
    assert_eq!(lab.snapshot().unwrap().active_peers,vec![10]);
    assert_eq!(lab.mode,GsmMode::CaughtUp);
    // The local selected economic history was independently fixed at
    // construction. This conditional test never chooses a winning branch.
}

#[test]
fn observed_peer_reorganization_revokes_verified_candidate_before_loe_rechecks(){
    let (_g,_,honest,other)=roots();
    let mut lab=EventDriven::new(&honest,1,config()).unwrap();
    lab.connect(10).unwrap();
    lab.connect(20).unwrap();
    lab.assume_honest_upstream(10).unwrap();
    let mut time=0;
    feed(&mut lab,10,&honest,&mut time);
    feed(&mut lab,20,&other,&mut time);
    let before=lab.snapshot().unwrap();
    assert_eq!(before.proposed_gdd_drops,vec![20]);
    // The SAME authenticated transport endpoint switches to another
    // independently produced signed original-genesis history. The actual
    // header response must be an explicit RollBack, not an invented tip.
    let q=lab.begin_poll(20).unwrap();
    let actual=respond(&honest,&q).unwrap();
    assert!(matches!(actual,Reply::RollBack{height:0,..}));
    time+=10;
    assert_eq!(lab.observe(20,actual,time,50),Ok(Observed::Rollback));
    let rollback=lab.snapshot().unwrap();
    assert_eq!(rollback.pending_economic_replay,vec![20]);
    assert!(rollback.source_trial.is_none());
    assert_eq!(lab.mode,GsmMode::Syncing);
    assert!(lab.records().iter().any(|entry|
        entry.id==Some(20)&&entry.why==Reason::ObservedRollback));
    feed(&mut lab,20,&honest,&mut time);
    let healed=lab.snapshot().unwrap();
    assert_eq!(healed.pending_economic_replay,Vec::<u16>::new());
    assert_eq!(healed.active_peers,vec![10,20]);
    assert!(healed.proposed_gdd_drops.is_empty());
    assert_eq!(lab.mode,GsmMode::CaughtUp);
}
