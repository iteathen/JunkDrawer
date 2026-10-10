//! Consensus-specific PZ-G1 tests: deterministic eligibility, historical
//! snapshots, exact crypto witnesses, fork rules, archival data, replay, and
//! original-genesis fail-closed recovery. NOT a GUC security theorem.
use algox_phase_zero::pz_g1::{
    Action,Chain,Error,Genesis,Profile,Prices,Proposer,Preference,
    SignedEvent,State,prefer,select_received,wins,
};
use ed25519_dalek::SigningKey;
use std::collections::BTreeMap;

fn key(b:u8)->SigningKey{SigningKey::from_bytes(&[b;32])}
fn profile()->Profile{
    Profile{network_salt:[17;32],slot_seconds:1,epoch_slots:8,
        k_blocks:1,s_slots:4,f_num:1,f_den:1,horizon:110,
        issue_base:3,issue_data:2,max_block_events:8,
        max_action_bytes:65536,max_core_steps:100,max_due_per_block:4,
        max_archive_bytes:65536,
        prices:Prices{per_byte:1,per_signature:1,per_core_step:0,
            per_state_byte:0,per_proof:0,per_terminal:2},
        core_digest:[7;32],runtime_digest:[8;32],
    }
}
fn fixture()->(Genesis,Proposer,SigningKey,SigningKey){
    let owner=key(1);let operator=key(2);
    let producer=Proposer::from_seeds([51;32],[52;32],operator.verifying_key().to_bytes()).unwrap();
    let mut accounts=BTreeMap::new();accounts.insert(owner.verifying_key().to_bytes(),1_000_000);
    accounts.insert(operator.verifying_key().to_bytes(),1_000_000);
    let genesis=Genesis{activation_unix_ms:None,profile:profile(),accounts,
       locked:vec![producer.credential(owner.verifying_key().to_bytes(),20,5000)]};
    (genesis,producer,owner,operator)
}
fn action(c:&Chain,key:&SigningKey,a:Action)->SignedEvent{
    SignedEvent::sign(&c.genesis.id(),key,
        c.state().account(&key.verifying_key().to_bytes()).nonce,0,a,None)
}
fn step(c:&mut Chain,p:&mut Proposer,slot:u64){
    c.produce(p,slot,vec![],true).unwrap();
}
#[test]
fn exact_integer_leadership_threshold_and_stake_split_math(){
    assert_eq!(wins(0,1,1,1,1),Ok(true));
    assert_eq!(wins(u64::MAX,1,1,1,1),Ok(true));
    assert_eq!(wins(0,1,2,1,2),Ok(true));
    assert_eq!(wins(u64::MAX,1,2,1,2),Ok(false));
    assert_eq!(wins(u64::MAX,0,2,1,2),Err(Error::Limit));
    assert_eq!(wins(0,2000,2000,1,2),Err(Error::Limit));
    for stake in 1..20{
        for vrf in [0,u64::MAX/8,u64::MAX/3,u64::MAX/2,u64::MAX-1]{
            // Higher weight cannot decrease the individual eligibility chance.
            if wins(vrf,stake,20,1,2).unwrap(){
                assert!(wins(vrf,stake+1,20,1,2).unwrap());
            }
        }
    }
}
#[test]
fn vrf_and_kes_signatures_are_bound_to_slot_genesis_and_body(){
    let (genesis,mut producer,_,_)=fixture();
    let mut chain=Chain::new(genesis.clone()).unwrap();
    step(&mut chain,&mut producer,1);
    step(&mut chain,&mut producer,2);
    let mut invalid=chain.blocks.clone();
    invalid[0].vrf_proof[1]^=1;
    assert!(Chain::replay(genesis.clone(),&invalid).is_err());
    let mut invalid=chain.blocks.clone();
    invalid[1].kes_signature[4]^=1;
    assert!(Chain::replay(genesis.clone(),&invalid).is_err());
    let mut invalid=chain.blocks.clone();
    invalid[1].state_root[0]^=1;
    assert!(Chain::replay(genesis.clone(),&invalid).is_err());
    let mut foreign=genesis.clone();foreign.profile.network_salt=[3;32];
    assert!(Chain::replay(foreign,&chain.blocks).is_err());
    assert_eq!(Chain::replay(genesis,&chain.blocks).unwrap().tip(),chain.tip());
}
#[test]
fn archival_response_requires_inclusion_in_old_cryptographically_bound_body(){
    let (genesis,mut producer,_,_)=fixture();
    let mut c=Chain::new(genesis.clone()).unwrap();
    step(&mut c,&mut producer,1);
    step(&mut c,&mut producer,2);
    assert_eq!(c.state().minted,6); // no non-genesis old chunk
    step(&mut c,&mut producer,3);
    assert_eq!(c.state().minted,11);
    let mut damaged=c.blocks.clone();
    let sample=damaged[2].archive.as_mut().unwrap();
    sample.bytes[0]^=1;
    assert!(Chain::replay(genesis.clone(),&damaged).is_err());
    let before=c.state().minted;
    c.produce(&mut producer,4,vec![],false).unwrap();
    assert_eq!(c.state().minted,before+3); // valid live block without archive
    c.state().assert_supply(&genesis).unwrap();
}
#[test]
fn bond_from_real_funds_only_then_exits_after_past_epoch_and_stable_blocks(){
    let (genesis,mut producer,owner,operator)=fixture();
    let mut c=Chain::new(genesis.clone()).unwrap();
    let new_operator=Proposer::from_seeds([88;32],[89;32],
        operator.verifying_key().to_bytes()).unwrap();
    let bond_tx=action(&c,&owner,Action::Bond{
        operator:operator.verifying_key().to_bytes(),
        vrf_public:new_operator.vrf_public,
        kes_public:new_operator.kes_public.clone(),
        amount:7,commission_bps:1000});
    c.produce(&mut producer,1,vec![bond_tx],true).unwrap();
    let stake_id=new_operator.credential(owner.verifying_key().to_bytes(),7,1000).id;
    assert_eq!(c.snapshot(0).unwrap().len(),1);
    assert_eq!(c.snapshot(1).unwrap().len(),1);
    let exit=action(&c,&owner,Action::Exit{id:stake_id});
    c.produce(&mut producer,2,vec![exit],true).unwrap();
    for slot in 3..=16 {step(&mut c,&mut producer,slot);}
    // Snapshot for e=2 uses e=0 end, after the exit: one credential.
    assert_eq!(c.snapshot(2).unwrap().len(),1);
    let withdraw=action(&c,&owner,Action::Withdraw{id:stake_id});
    let out=c.produce(&mut producer,17,vec![withdraw],true).unwrap();
    assert_ne!(out,[0u8;32]);
    // Once k blocks anchor an epoch beyond the last old eligible epoch,
    // the exit may be claimed without a vote by the former operator.
    assert!(!c.state().stake.contains_key(&stake_id));
    c.state().assert_supply(&genesis).unwrap();
}
#[test]
fn near_fork_switches_on_strict_length_only_and_deep_fork_on_early_density(){
    let (genesis,mut p,_,_)=fixture();
    let mut shared=Chain::new(genesis.clone()).unwrap();
    step(&mut shared,&mut p,1);
    let mut current=shared.clone();
    let mut alt=shared.clone();
    let mut a=Proposer::from_seeds([51;32],[52;32],key(2).verifying_key().to_bytes()).unwrap();
    let mut b=Proposer::from_seeds([51;32],[52;32],key(2).verifying_key().to_bytes()).unwrap();
    for slot in [2,4,6,8]{step(&mut current,&mut a,slot);}
    for slot in [3,4,5,6,8]{step(&mut alt,&mut b,slot);}
    assert_eq!(prefer(&current,&alt),Ok(Preference::Switch)); // 3 vs 2 in (1,5]
    assert_eq!(prefer(&alt,&current),Ok(Preference::Keep));
    let mut short=shared.clone();
    let mut shorter=Proposer::from_seeds([51;32],[52;32],key(2).verifying_key().to_bytes()).unwrap();
    step(&mut short,&mut shorter,2);
    assert_eq!(prefer(&shared,&short),Ok(Preference::Switch));
    assert_eq!(prefer(&short,&shared),Ok(Preference::Keep));
    assert_eq!(prefer(&short,&short),Ok(Preference::Keep));
}
#[test]
fn genesis_replay_rejects_forged_peer_history_and_stale_root_without_consensus(){
    let (genesis,mut p,_,_)=fixture();
    let mut good=Chain::new(genesis.clone()).unwrap();
    for slot in 1..=5 {step(&mut good,&mut p,slot);}
    let mut forged=good.blocks.clone();
    forged[1].state_root=[8;32];
    let selected=select_received(genesis.clone(),&[forged,good.blocks.clone()]).unwrap();
    assert_eq!(selected.tip(),good.tip());
    let bad_only=select_received(genesis.clone(),&[vec![good.blocks[0].clone(),
        good.blocks[1].clone()] ]).unwrap();
    assert!(bad_only.blocks.len()<good.blocks.len()); // can't infer current from receipt alone
    assert_eq!(select_received(genesis,&[]).err(),Some(Error::Unavailable));
}
#[test]
fn state_root_must_be_derived_by_independent_replay_not_asserted_by_header(){
    let (genesis,mut p,_,_)=fixture();
    let mut c=Chain::new(genesis.clone()).unwrap();
    step(&mut c,&mut p,1);
    let old_root=c.state().root();
    let forged=State::from_genesis(&genesis).unwrap();
    assert_eq!(c.verify_checkpoint(&forged,1),Err(Error::InvalidProof));
    assert_eq!(c.state().root(),old_root);
}

#[test]
fn delegated_stake_ownership_and_operator_keys_rotate_without_duplicate_weight(){
    let (genesis,mut old_producer,owner,old_operator)=fixture();
    let old_id=genesis.locked[0].id;
    let new_owner=key(55);
    let mut new_producer=Proposer::from_seeds([93;32],[94;32],
        key(56).verifying_key().to_bytes()).unwrap();
    let next=Action::RotateStake{
        id:old_id,new_owner:Some(new_owner.verifying_key().to_bytes()),
        new_operator:new_producer.operator,
        new_vrf:new_producer.vrf_public,
        new_kes:new_producer.kes_public.clone(),commission_bps:1500,
    };
    let mut c=Chain::new(genesis.clone()).unwrap();
    let unauthorized=action(&c,&old_operator,next.clone());
    c.produce(&mut old_producer,1,vec![unauthorized],false).unwrap();
    assert_eq!(c.blocks[0].results[0],
        algox_phase_zero::pz_g1::Outcome::Charged(Error::Unauthorized));
    assert!(c.state().stake.contains_key(&old_id));
    let authorized=action(&c,&owner,next);
    c.produce(&mut old_producer,2,vec![authorized],false).unwrap();
    let new_id=new_producer.credential(new_owner.verifying_key().to_bytes(),20,1500).id;
    assert!(!c.state().stake.contains_key(&old_id));
    assert!(c.state().stake.contains_key(&new_id));
    assert_eq!(c.snapshot(0).unwrap()[0].id,old_id);
    assert_eq!(c.snapshot(1).unwrap()[0].id,old_id);
    for slot in 3..16 {
        c.produce(&mut old_producer,slot,vec![],false).unwrap();
    }
    assert_eq!(c.snapshot(2).unwrap()[0].id,new_id);
    c.produce(&mut new_producer,16,vec![],false).unwrap();
    let before=c.state().root();
    assert!(c.produce(&mut old_producer,17,vec![],false).is_err());
    assert_eq!(c.state().root(),before);
    c.state().assert_supply(&genesis).unwrap();
}

#[test]
fn incomplete_deep_fork_comparison_refuses_to_claim_a_current_history(){
    let (genesis,mut proposer,_,operator)=fixture();
    let mut root=Chain::new(genesis.clone()).unwrap();
    step(&mut root,&mut proposer,1);
    let mut selected=root.clone();
    let mut rival=root.clone();
    let mut first=Proposer::from_seeds([51;32],[52;32],
        operator.verifying_key().to_bytes()).unwrap();
    let mut other=Proposer::from_seeds([51;32],[52;32],
        operator.verifying_key().to_bytes()).unwrap();
    for slot in [2,3]{step(&mut selected,&mut first,slot);}
    for slot in [3,4]{step(&mut rival,&mut other,slot);}
    assert_eq!(prefer(&selected,&rival),Ok(Preference::NeedHistory));
    assert_eq!(select_received(genesis,&[
        selected.blocks.clone(),rival.blocks.clone()
    ]).err(),Some(Error::Unavailable));
}

#[test]
fn archive_selection_is_fixed_width_not_host_usize_modulo(){
    // On wasm32 casting high-entropy u64 to usize before reducing modulo
    // 3 discarded the top half, diverging from 64-bit native block headers.
    let (genesis,mut producer,_,_)=fixture();
    let mut chain=Chain::new(genesis.clone()).unwrap();
    for slot in 1..=4{step(&mut chain,&mut producer,slot);}
    let output=[53u8;64];
    let mut observed_truncation_case=false;
    for slot in 5u64..=40 {
        let randomness=algox_phase_zero::pz_g1::digest(
            b"AlgoX/PZ-G1/archive-challenge/v1",
            &[&genesis.id(),&chain.tip(),&slot.to_le_bytes(),&output]);
        let draw=u64::from_be_bytes(randomness[..8].try_into().unwrap());
        let eligible=(chain.blocks.len()-genesis.profile.k_blocks as usize) as u64;
        let canonical=(draw%eligible) as usize;
        let wrong=((draw as u32 as u64)%eligible) as usize;
        let chosen=chain.archive_challenge(slot,&output).unwrap().unwrap().0;
        assert_eq!(chosen,canonical);
        if canonical!=wrong {observed_truncation_case=true;}
    }
    assert!(observed_truncation_case,
        "The regression must include high-32-bit entropy influencing modulo");
}

#[test]
fn authentic_clock_completes_density_window_even_when_sparse_chain_stopped(){
    use algox_phase_zero::pz_g1::{prefer_at_slot,select_received_at_slot};
    let (genesis,mut first,_,operator)=fixture();
    let mut common=Chain::new(genesis.clone()).unwrap();
    step(&mut common,&mut first,1);
    let mut sparse=common.clone();
    let mut denser=common.clone();
    let mut a=Proposer::from_seeds([51;32],[52;32],
        operator.verifying_key().to_bytes()).unwrap();
    let mut b=Proposer::from_seeds([51;32],[52;32],
        operator.verifying_key().to_bytes()).unwrap();
    for slot in [2,4]{step(&mut sparse,&mut a,slot);}
    for slot in [3,4,5]{step(&mut denser,&mut b,slot);}
    // The original tip-only API cannot prove that the sparse branch has
    // reached the window's end (slot 5), and must conservatively abstain.
    assert_eq!(prefer(&sparse,&denser),Ok(Preference::NeedHistory));
    // A trusted host clock at slot 7 *does* prove that the first four
    // post-intersection slots elapsed, even if a branch has no new blocks.
    assert_eq!(prefer_at_slot(&sparse,&denser,7),Ok(Preference::Switch));
    let candidates=[sparse.blocks.clone(),denser.blocks.clone()];
    let chosen=select_received_at_slot(genesis.clone(),&candidates,7).unwrap();
    assert_eq!(chosen.tip(),denser.tip());
    assert_eq!(prefer_at_slot(&sparse,&denser,4),Err(Error::InvalidBlock));
    // The same choice must survive canonical byte decoding under a
    // separately expected original-genesis identity.
    let wires=candidates.iter().map(|branch|
        branch.iter().map(|block|block.encode_wire()).collect::<Vec<_>>()
    ).collect::<Vec<_>>();
    let received=Chain::fresh_from_received(genesis.clone(),&genesis.id(),
        7,2,&wires).unwrap();
    assert_eq!(received.tip(),denser.tip());
}

#[test]
fn untrusted_kes_failure_precedes_heavy_economic_root_recomputation(){
    let (genesis,mut producer,_,_)=fixture();
    let mut author=Chain::new(genesis.clone()).unwrap();
    step(&mut author,&mut producer,1);
    let mut forged=author.blocks[0].clone();
    // The economic state root is inconsistent, but an unauthenticated block
    // must fail at its cheaply checkable producer signature, before replay.
    forged.state_root=[99;32];
    forged.proof_root=[98;32];
    forged.kes_signature[0]^=1;
    let mut verifier=Chain::new(genesis).unwrap();
    assert_eq!(verifier.append(forged),Err(Error::InvalidProof));
    assert_eq!(verifier.blocks.len(),0);
    assert_eq!(verifier.state().minted,0);
}

#[test]
fn witness_source_gap_deep_fork_equal_early_window_is_permanent_mutual_keep(){
    // Reproduces the 40 live-process experiment's independently audited
    // structural failure: both histories are perfectly valid and readable,
    // but the simplified research comparator returns Keep in BOTH directions
    // when the first s post-intersection slots contain no blocks. A longer
    // fully authentic history cannot repair that deadlock after quiescence.
    let (genesis,mut common_proposer,_,operator)=fixture();
    let mut common=Chain::new(genesis.clone()).unwrap();
    step(&mut common,&mut common_proposer,1);
    let mut a=common.clone();
    let mut b=common.clone();
    let mut a_signer=Proposer::from_seeds([51;32],[52;32],
        operator.verifying_key().to_bytes()).unwrap();
    let mut b_signer=Proposer::from_seeds([51;32],[52;32],
        operator.verifying_key().to_bytes()).unwrap();
    for slot in [6,8,9,10]{step(&mut a,&mut a_signer,slot);}
    for slot in [7,9,11]{step(&mut b,&mut b_signer,slot);}
    assert_eq!(a.blocks.len(),5);
    assert_eq!(b.blocks.len(),4);
    assert_ne!(a.tip(),b.tip());
    let imported_a=Chain::replay(genesis.clone(),&a.blocks).unwrap();
    let imported_b=Chain::replay(genesis,&b.blocks).unwrap();
    use algox_phase_zero::pz_g1::consensus::prefer_at_slot;
    assert_eq!(prefer_at_slot(&imported_a,&imported_b,50),Ok(Preference::Keep));
    assert_eq!(prefer_at_slot(&imported_b,&imported_a,50),Ok(Preference::Keep));
    // This is a *detected unsatisfied acceptance obligation*, not a
    // solution or theorem. A future source-faithful fork-rule repair must
    // revisit this fixture and the measured real-network counterexample.
}
