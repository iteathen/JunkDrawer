//! Experiment 022 genuine VRF/KES signed-chain wire observations.
//! The observational peer header poll NEVER confers ledger selection power.
use algox_phase_zero::pz_g1::{Chain,Genesis,Profile,Prices,Proposer,Error};
use algox_phase_zero::pz_g1::chain_sync_observe::{
    Reply,PeerCursor,Observed,respond,encode_query,OPCODE,
};
use ed25519_dalek::SigningKey;
use std::collections::BTreeMap;
fn key(b:u8)->SigningKey{SigningKey::from_bytes(&[b;32])}
fn sample()->(Genesis,Proposer){
    let owner=key(1);let operator=key(2);
    let signer=Proposer::from_seeds([51;32],[52;32],
        operator.verifying_key().to_bytes()).unwrap();
    let mut accounts=BTreeMap::new();
    accounts.insert(owner.verifying_key().to_bytes(),1_000_000);
    accounts.insert(operator.verifying_key().to_bytes(),1_000_000);
    (Genesis{
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
        locked:vec![signer.credential(owner.verifying_key().to_bytes(),20,5000)],
    },signer)
}
fn grow(chain:&mut Chain,signer:&mut Proposer,slots:&[u64]){
    for &slot in slots{chain.produce(signer,slot,vec![],true).unwrap();}
}
#[test]
fn real_block_headers_can_be_observed_but_await_is_not_finality(){
    let (g,mut signer)=sample();
    let mut chain=Chain::new(g.clone()).unwrap();
    grow(&mut chain,&mut signer,&[1,2,3]);
    let verified=Chain::replay(g.clone(),&chain.blocks).unwrap();
    let mut observed=PeerCursor::new(g.id());
    for i in 0..3 {
        let q=observed.query();
        let x=respond(&chain,&q).unwrap();
        let encoded=x.encode();
        assert_eq!(Reply::decode(&encoded).unwrap(),x);
        assert_eq!(observed.observe(x,10,g.profile.horizon as usize),
            Ok(Observed::Forward));
        assert_eq!(observed.height(),i+1);
    }
    let reply=respond(&chain,&observed.query()).unwrap();
    assert!(matches!(reply,Reply::AwaitReply{height:3,..}));
    assert_eq!(observed.observe(reply,10,110),Ok(Observed::Await));
    assert!(observed.awaiting());
    assert_eq!(observed.observe(reply,10,110),Ok(Observed::RepeatedAwait));
    assert!(observed.matches_verified_chain(&verified));
    assert_eq!(observed.verified_prefix(&verified),3);
    // AwaitReply authenticates neither the current network nor HAA.
}
#[test]
fn actual_reorganization_requires_explicit_network_roll_back(){
    let (g,mut signer)=sample();
    let mut common=Chain::new(g.clone()).unwrap();
    grow(&mut common,&mut signer,&[1]);
    let mut a=common.clone();let mut b=common.clone();
    let mut pa=Proposer::from_seeds([51;32],[52;32],key(2).verifying_key().to_bytes()).unwrap();
    let mut pb=Proposer::from_seeds([51;32],[52;32],key(2).verifying_key().to_bytes()).unwrap();
    grow(&mut a,&mut pa,&[2,4,6]);
    grow(&mut b,&mut pb,&[3,5,7]);
    let b_verified=Chain::replay(g.clone(),&b.blocks).unwrap();
    let mut cursor=PeerCursor::new(g.id());
    for _ in 0..a.blocks.len(){
        let reply=respond(&a,&cursor.query()).unwrap();
        assert_eq!(cursor.observe(reply,15,110),Ok(Observed::Forward));
    }
    assert!(!cursor.matches_verified_chain(&b_verified));
    let divergence=respond(&b,&cursor.query()).unwrap();
    assert_eq!(divergence,Reply::RollBack{height:0,tip:g.id()});
    assert_eq!(cursor.observe(divergence,15,110),Ok(Observed::Rollback));
    assert_eq!(cursor.height(),0);
    for _ in 0..b.blocks.len(){
        let msg=respond(&b,&cursor.query()).unwrap();
        assert_eq!(cursor.observe(msg,15,110),Ok(Observed::Forward));
    }
    assert!(cursor.matches_verified_chain(&b_verified));
    assert_eq!(cursor.tip(),b.tip());
}
#[test]
fn malformed_untrusted_messages_and_future_headers_fail_closed_without_state_mutation(){
    let (g,mut signer)=sample();
    let mut c=Chain::new(g.clone()).unwrap();
    grow(&mut c,&mut signer,&[1]);
    let mut cursor=PeerCursor::new(g.id());
    let q=cursor.query();
    assert_eq!(q.len(),37);
    assert_eq!(q[0],OPCODE);
    assert_eq!(respond(&c,&[]),Err(Error::Malformed));
    assert_eq!(respond(&c,&q[..36]),Err(Error::Malformed));
    let mut bad=q.clone();bad[0]^=1;
    assert_eq!(respond(&c,&bad),Err(Error::Malformed));
    assert_eq!(Reply::decode(&[1]),Err(Error::Malformed));
    assert_eq!(Reply::decode(&[4;37]),Err(Error::Malformed));
    assert_eq!(Reply::decode(&[1;78]),Err(Error::Malformed));
    let header=respond(&c,&q).unwrap();
    assert_eq!(cursor.observe(header,0,110),Err(Error::InvalidProof));
    assert_eq!(cursor.height(),0);
    assert_eq!(cursor.observe(header,1,0),Err(Error::InvalidProof));
    assert_eq!(cursor.height(),0);
    assert_eq!(cursor.observe(header,1,110),Ok(Observed::Forward));
    assert_eq!(cursor.observe(header,1,110),Err(Error::InvalidProof));
    assert_eq!(cursor.height(),1);
    let wrong=Reply::AwaitReply{height:2,tip:c.tip()};
    assert_eq!(cursor.observe(wrong,2,110),Err(Error::InvalidProof));
    assert!(!cursor.awaiting());
    let malformed=Reply::RollBack{height:1,tip:g.id()};
    assert_eq!(cursor.observe(malformed,2,110),Err(Error::InvalidProof));
    assert_eq!(cursor.height(),1);
}
#[test]
fn request_cursors_cannot_manufacture_original_genesis_authority(){
    let (g,_)=sample();
    let c=Chain::new(g.clone()).unwrap();
    let mut q=encode_query(100,&g.id());
    assert_eq!(respond(&c,&q).unwrap(),Reply::RollBack{height:0,tip:g.id()});
    q=encode_query(0,&[33;32]);
    assert_eq!(respond(&c,&q).unwrap(),Reply::RollBack{height:0,tip:g.id()});
    let mut cursor=PeerCursor::new(g.id());
    assert_eq!(cursor.observe(Reply::RollBack{height:0,tip:g.id()},1,110),
        Err(Error::InvalidProof));
    assert_eq!(cursor.observe(Reply::AwaitReply{height:0,tip:g.id()},0,110),
        Ok(Observed::Await));
    // The empty-genesis chain can honestly have zero headers; absence of
    // further reported headers is not current or canonical history proof.
}
#[test]
fn peer_claims_need_independent_full_economic_replay_to_correlate(){
    let (g,mut p)=sample();
    let mut c=Chain::new(g.clone()).unwrap();
    grow(&mut c,&mut p,&[1,2]);
    let mut cursor=PeerCursor::new(g.id());
    let signed=Chain::replay(g.clone(),&c.blocks).unwrap();
    let wire=cursor.query();
    let next=respond(&c,&wire).unwrap();
    assert_eq!(cursor.observe(next,4,110),Ok(Observed::Forward));
    assert!(cursor.matches_verified_chain(&signed));
    let mut alternate=c.clone();
    alternate.blocks[0].state_root=[54;32];
    // Stale/header-consistent claims are not accepted from a forged
    // economic root; independently replaying that body must fail.
    assert!(Chain::replay(g,&alternate.blocks).is_err());
}
