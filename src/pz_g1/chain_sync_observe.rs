//! Experiment 022: bounded, observational ChainSync-like HEADER POLLS.
//!
//! The wire carries UNTRUSTED claims about a remote node's headers. Neither
//! signed HELLO authentication nor these records authenticates a current chain,
//! paid work, consensus history or a genuine source HAA. An observer can
//! correlate the claims ONLY with a separately fully replayed PZ-G1 Chain.
//! This is NOT Cardano's persistent ChainSync mini-protocol; the GDD/GSM source
//! correspondence must still be justified separately.
use super::{Chain,Hash,Error,PzResult};

pub const OPCODE:u8=12;
const REQUEST_LEN:usize=1+4+32;
const INDEX_LEN:usize=1+4+32;
const FORWARD_LEN:usize=1+4+8+32+32;

#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct Header{
    pub height:u32,
    pub slot:u64,
    pub id:Hash,
    pub parent:Hash,
}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub enum Reply {
    RollForward(Header),
    AwaitReply{height:u32,tip:Hash},
    RollBack{height:u32,tip:Hash},
}
impl Reply {
    pub fn encode(self)->Vec<u8>{
        let mut bytes=Vec::with_capacity(FORWARD_LEN);
        match self {
            Self::RollForward(h)=>{
                bytes.push(1);bytes.extend(h.height.to_le_bytes());
                bytes.extend(h.slot.to_le_bytes());
                bytes.extend(h.id);bytes.extend(h.parent);
            },
            Self::AwaitReply{height,tip}=>{
                bytes.push(2);bytes.extend(height.to_le_bytes());bytes.extend(tip);
            },
            Self::RollBack{height,tip}=>{
                bytes.push(3);bytes.extend(height.to_le_bytes());bytes.extend(tip);
            }
        }
        bytes
    }
    pub fn decode(wire:&[u8])->PzResult<Self>{
        if wire.is_empty(){return Err(Error::Malformed);}
        match (wire[0],wire.len()){
            (1,FORWARD_LEN)=>Ok(Self::RollForward(Header{
                height:u32::from_le_bytes(wire[1..5].try_into().unwrap()),
                slot:u64::from_le_bytes(wire[5..13].try_into().unwrap()),
                id:wire[13..45].try_into().unwrap(),
                parent:wire[45..77].try_into().unwrap(),
            })),
            (2,INDEX_LEN)=>Ok(Self::AwaitReply{
                height:u32::from_le_bytes(wire[1..5].try_into().unwrap()),
                tip:wire[5..37].try_into().unwrap(),
            }),
            (3,INDEX_LEN)=>Ok(Self::RollBack{
                height:u32::from_le_bytes(wire[1..5].try_into().unwrap()),
                tip:wire[5..37].try_into().unwrap(),
            }),
            _=>Err(Error::Malformed),
        }
    }
}
pub fn encode_query(height:u32,tip:&Hash)->Vec<u8>{
    let mut b=Vec::with_capacity(REQUEST_LEN);
    b.push(OPCODE);b.extend(height.to_le_bytes());b.extend(tip);
    b
}
pub fn respond(chain:&Chain,request:&[u8])->PzResult<Reply>{
    if request.len()!=REQUEST_LEN || request[0]!=OPCODE{
        return Err(Error::Malformed);
    }
    let height=u32::from_le_bytes(request[1..5].try_into().unwrap());
    let known:Hash=request[5..37].try_into().unwrap();
    let genesis=chain.genesis.id();
    let n=chain.blocks.len();
    let cursor=usize::try_from(height).map_err(|_|Error::Limit)?;
    // A remote participant may supply inconsistent/misleading bytes: the
    // receiver NEVER adopts this as a chain. Reset to GENESIS on mismatch.
    // A full source protocol would find intersections more efficiently.
    let actual=if cursor==0{genesis}
       else{chain.blocks.get(cursor-1)
           .map(|b|b.id(&genesis)).unwrap_or(genesis)};
    if cursor>n || known!=actual {
        return Ok(Reply::RollBack{height:0,tip:genesis});
    }
    if cursor==n {
        return Ok(Reply::AwaitReply{height,tip:actual});
    }
    let block=&chain.blocks[cursor];
    Ok(Reply::RollForward(Header{
        height:height.checked_add(1).ok_or(Error::Overflow)?,
        slot:block.slot,id:block.id(&genesis),parent:block.parent,
    }))
}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub enum Observed { Forward, Await, RepeatedAwait, Rollback }
/// Bytes observed from ONE individually authenticated transport endpoint.
/// The Header vector is NOT cryptographically verified by this struct.
#[derive(Clone,Debug,Eq,PartialEq)]
pub struct PeerCursor{
    genesis:Hash,
    headers:Vec<Header>,
    awaiting:bool,
}
impl PeerCursor{
    pub fn new(genesis:Hash)->Self{
        Self{genesis,headers:Vec::new(),awaiting:false}
    }
    pub fn height(&self)->usize{self.headers.len()}
    pub fn tip(&self)->Hash{
        self.headers.last().map_or(self.genesis,|h|h.id)
    }
    pub fn awaiting(&self)->bool{self.awaiting}
    pub fn query(&self)->Vec<u8>{
        encode_query(self.headers.len() as u32,&self.tip())
    }
    pub fn observe(&mut self,msg:Reply,observed_slot:u64,max_headers:usize)
        ->PzResult<Observed>{
        // Failed observation never mutates the previously recorded cursor.
        match msg{
            Reply::RollForward(h)=>{
                if self.headers.len()>=max_headers ||
                   h.height as usize!=self.headers.len()+1 ||
                   h.slot>observed_slot || h.slot==0 ||
                   h.parent!=self.tip() ||
                   self.headers.last().is_some_and(|prev|h.slot<=prev.slot){
                    return Err(Error::InvalidProof);
                }
                self.headers.push(h);
                self.awaiting=false;
                Ok(Observed::Forward)
            },
            Reply::AwaitReply{height,tip}=>{
                if height as usize!=self.headers.len() || tip!=self.tip(){
                    return Err(Error::InvalidProof);
                }
                let outcome=if self.awaiting{
                    Observed::RepeatedAwait
                }else{Observed::Await};
                self.awaiting=true;
                Ok(outcome)
            },
            Reply::RollBack{height,tip}=>{
                if height!=0 || tip!=self.genesis || self.headers.is_empty(){
                    return Err(Error::InvalidProof);
                }
                self.headers.clear();self.awaiting=false;
                Ok(Observed::Rollback)
            }
        }
    }
    /// This ONLY corroborates already observed untrusted header bytes with
    /// independently cryptographically FULLY REPLAYED original-genesis blocks.
    /// In particular, a peer's claimed `AwaitReply` does not mean it was
    /// actually current or that its history is the network's chosen chain.
    pub fn verified_prefix(&self,chain:&Chain)->usize{
        if chain.genesis.id()!=self.genesis{return 0;}
        self.headers.iter().zip(&chain.blocks).take_while(|(h,b)|
            h.slot==b.slot && h.parent==b.parent &&
            h.id==b.id(&self.genesis)).count()
    }
    pub fn matches_verified_chain(&self,chain:&Chain)->bool{
        self.genesis==chain.genesis.id() &&
        self.headers.len()<=chain.blocks.len() &&
        self.verified_prefix(chain)==self.headers.len()
    }
}
