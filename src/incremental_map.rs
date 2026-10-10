//! Public extracted authenticated Patricia map and typed proof codecs.
//! Matches source member/absence proof implementation; fixture-only.
use crate::{Failure,Result,Reader};
use sha2::{Digest,Sha256};
type Hash32=[u8;32];
const KEY_TAG:&[u8]=b"AlgoX-PhaseZero/patricia-key/v1\0";
const LEAF_TAG:&[u8]=b"AlgoX-PhaseZero/patricia-leaf/v1\0";
const NODE_TAG:&[u8]=b"AlgoX-PhaseZero/patricia-branch/v1\0";
const ROOT_TAG:&[u8]=b"AlgoX-PhaseZero/patricia-root/v1\0";
const EMPTY_TAG:&[u8]=b"AlgoX-PhaseZero/patricia-empty/v1\0";
const MAX_ITEMS:usize=100_000; // isolated research resource bound
const MAX_VALUE:usize=32_768; // same provisional v1 record-value bound

fn hash(parts:&[&[u8]])->Hash32 {
    let mut h=Sha256::new();
    for p in parts {h.update(p);}
    h.finalize().into()
}
fn valid_key(key:&[u8])->bool {
    match key.first(){
        Some(0)=>key.len()==1,
        Some(1|5|6)=>key.len()==33,
        Some(2..=4)=>key.len()==9,
        _=>false,
    }
}
fn checked_size(n:usize)->Result<[u8;4]>{
    Ok(u32::try_from(n).map_err(|_|Failure::Overflow)?.to_le_bytes())
}
fn key_hash(key:&[u8])->Result<Hash32>{
    Ok(hash(&[KEY_TAG,&checked_size(key.len())?,key]))
}
fn leaf_hash(key:&[u8],value:&[u8])->Result<Hash32>{
    Ok(hash(&[LEAF_TAG,&checked_size(key.len())?,key,
                &checked_size(value.len())?,value]))
}
fn branch_hash(bit:u16,left:&Hash32,right:&Hash32)->Hash32 {
    hash(&[NODE_TAG,&bit.to_le_bytes(),left,right])
}
fn root_hash(count:usize,top:&Hash32)->Hash32 {
    hash(&[ROOT_TAG,&(count as u64).to_le_bytes(),top])
}
fn empty_top()->Hash32 {hash(&[EMPTY_TAG])}
fn which(hash:&Hash32,bit:u16)->u8 {
    let at=usize::from(bit / 8);
    (hash[at]>>(7-(bit%8)))&1
}
fn first_difference(a:&Hash32,b:&Hash32)->Option<u16>{
    for (i,(&x,&y)) in a.iter().zip(b).enumerate() {
        if x!=y {
            return Some((i*8+(x^y).leading_zeros() as usize) as u16);
        }
    }
    None
}
#[derive(Clone)]
enum Node {
    Leaf {key:Vec<u8>,value:Vec<u8>,key_digest:Hash32,digest:Hash32},
    Branch {bit:u16,left:Box<Node>,right:Box<Node>,digest:Hash32},
}
impl Node {
    fn digest(&self)->Hash32{
        match self{Self::Leaf{digest,..}|Self::Branch{digest,..}=>*digest}
    }
    fn join(bit:u16,left:Box<Node>,right:Box<Node>)->Box<Node>{
        let digest=branch_hash(bit,&left.digest(),&right.digest());
        Box::new(Self::Branch{bit,left,right,digest})
    }
    fn leaf(key:Vec<u8>,value:Vec<u8>,key_digest:Hash32)->Result<Box<Node>>{
        let digest=leaf_hash(&key,&value)?;
        Ok(Box::new(Self::Leaf{key,value,key_digest,digest}))
    }
    fn reached<'a>(&'a self,kh:&Hash32)->&'a Node{
        match self{
            Self::Leaf{..}=>self,
            Self::Branch{bit,left,right,..}=>{
                if which(kh,*bit)==0 {left.reached(kh)} else {right.reached(kh)}
            }
        }
    }
    fn replace(&mut self,kh:&Hash32,value:Vec<u8>)->Result<usize>{
        match self{
            Self::Leaf{key,value:old,digest,..}=>{
                *old=value;
                *digest=leaf_hash(key,old)?;
                Ok(1)
            },
            Self::Branch{bit,left,right,digest}=>{
                let path_hashes=if which(kh,*bit)==0 {left.replace(kh,value)?}
                    else {right.replace(kh,value)?};
                *digest=branch_hash(*bit,&left.digest(),&right.digest());
                Ok(path_hashes+1)
            }
        }
    }
    // The canonical split is the FIRST differing hashed-key bit. Recurse
    // only below earlier existing split bits; splice at the divergence.
    fn splice(node:Box<Node>,new:Box<Node>,split:u16,kh:&Hash32)->(Box<Node>,usize){
        match *node {
            Self::Branch{bit,left,right,..} if bit<split=>{
                if which(kh,bit)==0 {
                    let (updated,cost)=Self::splice(left,new,split,kh);
                    (Self::join(bit,updated,right),cost+1)
                } else {
                    let (updated,cost)=Self::splice(right,new,split,kh);
                    (Self::join(bit,left,updated),cost+1)
                }
            },
            existing=>{
                let original=Box::new(existing);
                if which(kh,split)==0 {(Self::join(split,new,original),1)}
                else {(Self::join(split,original,new),1)}
            }
        }
    }
    fn remove(node:Box<Node>,kh:&Hash32)->(Option<Box<Node>>,usize){
        match *node {
            Self::Leaf{..}=>(None,0),
            Self::Branch{bit,left,right,..}=>{
                if which(kh,bit)==0 {
                    let (remaining,cost)=Self::remove(left,kh);
                    match remaining {
                        None=>(Some(right),cost),
                        Some(new_left)=>(Some(Self::join(bit,new_left,right)),cost+1),
                    }
                } else {
                    let (remaining,cost)=Self::remove(right,kh);
                    match remaining {
                        None=>(Some(left),cost),
                        Some(new_right)=>(Some(Self::join(bit,left,new_right)),cost+1),
                    }
                }
            }
        }
    }
    fn depth(&self)->usize{
        match self {
            Self::Leaf{..}=>0,
            Self::Branch{left,right,..}=>1+left.depth().max(right.depth())
        }
    }
}
#[derive(Clone,Debug,PartialEq,Eq)]
pub struct PathStep {
    pub bit:u16,
    pub sibling:Hash32,
}
#[derive(Clone,Debug,PartialEq,Eq)]
pub struct MemberProof {
    pub key:Vec<u8>,
    pub value:Vec<u8>,
    pub count:u64,
    // From root toward the leaf. Directions derive from the hashed key.
    pub path:Vec<PathStep>,
}
impl MemberProof {
    pub fn verify(&self,expected_root:&Hash32)->Result<()>{
        if self.count==0 || self.count>MAX_ITEMS as u64 ||
           !valid_key(&self.key) || self.value.len()>MAX_VALUE ||
           self.path.len()>256 {return Err(Failure::Malformed);}
        let kh=key_hash(&self.key)?;
        let mut previous=None;
        for step in &self.path {
            if step.bit>=256 || previous.is_some_and(|bit|step.bit<=bit) {
                return Err(Failure::Malformed);
            }
            previous=Some(step.bit);
        }
        let mut digest=leaf_hash(&self.key,&self.value)?;
        for step in self.path.iter().rev(){
            digest=if which(&kh,step.bit)==0 {
                branch_hash(step.bit,&digest,&step.sibling)
            } else {
                branch_hash(step.bit,&step.sibling,&digest)
            };
        }
        if root_hash(self.count as usize,&digest)!=*expected_root {
            return Err(Failure::EvidenceMismatch);
        }
        Ok(())
    }
}
#[derive(Clone,Debug,PartialEq,Eq)]
pub struct AbsentProof {
    pub queried_key:Vec<u8>,
    // The unique reached leaf when this key's bits traverse the trie.
    pub reached:Option<MemberProof>,
}
impl AbsentProof {
    pub fn verify(&self,expected_root:&Hash32)->Result<()>{
        if !valid_key(&self.queried_key){return Err(Failure::Malformed);}
        let Some(member)=&self.reached else {
            if *expected_root==root_hash(0,&empty_top()) {return Ok(());}
            return Err(Failure::EvidenceMismatch);
        };
        member.verify(expected_root)?;
        if self.queried_key==member.key {return Err(Failure::EvidenceMismatch);}
        let query_hash=key_hash(&self.queried_key)?;
        let witness_hash=key_hash(&member.key)?;
        if query_hash==witness_hash {return Err(Failure::EvidenceMismatch);}
        // A membership witness for an unrelated leaf is not an absence proof:
        // every authenticated branch must route the queried key to the SAME
        // singleton leaf. Merely omitting its first differing bit is unsafe.
        for branch in &member.path{
            if which(&query_hash,branch.bit)!=which(&witness_hash,branch.bit){
                return Err(Failure::EvidenceMismatch);
            }
        }
        Ok(())
    }
}

/// O(depth) expected path-local insert/update/delete. Root queries never
/// rebuild the tree. The explicit state transitions must still be validated.
#[derive(Clone,Default)]
pub struct PatriciaMap {
    root:Option<Box<Node>>,
    count:usize,
    last_mutation_hashes:usize, // test-only trace, not consensus pricing
}
impl PatriciaMap {
    pub fn new()->Self{Self::default()}
    pub fn len(&self)->usize{self.count}
    pub fn is_empty(&self)->bool{self.count==0}
    pub fn last_mutation_hashes(&self)->usize{self.last_mutation_hashes}
    pub fn max_depth(&self)->usize{
        self.root.as_ref().map_or(0,|node|node.depth())
    }
    pub fn root(&self)->Hash32{
        root_hash(self.count,&self.root.as_ref()
                  .map_or_else(empty_top,|n|n.digest()))
    }
    pub fn get(&self,key:&[u8])->Option<&[u8]>{
        if !valid_key(key){return None;}
        let kh=key_hash(key).ok()?;
        match self.root.as_ref()?.reached(&kh){
            Node::Leaf{key:actual,value,..} if actual==key=>Some(value),
            _=>None,
        }
    }
    pub fn upsert(&mut self,key:Vec<u8>,value:Vec<u8>)->Result<()>{
        if !valid_key(&key) || value.len()>MAX_VALUE {
            return Err(Failure::Malformed);
        }
        let kh=key_hash(&key)?;
        let Some(root)=self.root.as_ref() else {
            self.root=Some(Node::leaf(key,value,kh)?);
            self.count=1;
            self.last_mutation_hashes=1;
            return Ok(());
        };
        let (neighbor_key,neighbor_digest)=match root.reached(&kh){
            Node::Leaf{key,key_digest,..}=>(key.clone(),*key_digest),
            Node::Branch{..}=>return Err(Failure::Malformed),
        };
        if neighbor_digest==kh {
            if neighbor_key!=key{return Err(Failure::EvidenceMismatch);}
            self.last_mutation_hashes=self.root.as_mut()
                .ok_or(Failure::Malformed)?.replace(&kh,value)?;
            return Ok(());
        }
        if self.count>=MAX_ITEMS{return Err(Failure::ResourceExhausted);}
        let split=first_difference(&kh,&neighbor_digest)
            .ok_or(Failure::EvidenceMismatch)?;
        let leaf=Node::leaf(key,value,kh)?;
        let old=self.root.take().ok_or(Failure::Malformed)?;
        let (updated,cost)=Node::splice(old,leaf,split,&kh);
        self.root=Some(updated);
        self.last_mutation_hashes=cost+1; // new leaf + path branches
        self.count+=1;
        Ok(())
    }
    pub fn remove(&mut self,key:&[u8])->Result<()>{
        if !valid_key(key){return Err(Failure::Malformed);}
        if self.get(key).is_none(){return Err(Failure::Unavailable);}
        let kh=key_hash(key)?;
        let old=self.root.take().ok_or(Failure::Malformed)?;
        let (updated,cost)=Node::remove(old,&kh);
        self.root=updated;
        self.last_mutation_hashes=cost;
        self.count-=1;
        Ok(())
    }
    pub fn membership(&self,key:&[u8])->Result<MemberProof>{
        if !valid_key(key){return Err(Failure::Malformed);}
        let kh=key_hash(key)?;
        let mut steps=Vec::new();
        let mut node=self.root.as_ref().ok_or(Failure::Unavailable)?.as_ref();
        loop {
            match node {
                Node::Leaf{key:actual,value,..}=>{
                    if actual!=key{return Err(Failure::Unavailable);}
                    return Ok(MemberProof{key:actual.clone(),value:value.clone(),
                               count:self.count as u64,path:steps});
                },
                Node::Branch{bit,left,right,..}=>{
                    if which(&kh,*bit)==0 {
                        steps.push(PathStep{bit:*bit,sibling:right.digest()});
                        node=left;
                    }else{
                        steps.push(PathStep{bit:*bit,sibling:left.digest()});
                        node=right;
                    }
                }
            }
        }
    }
    pub fn absence(&self,key:&[u8])->Result<AbsentProof>{
        if !valid_key(key){return Err(Failure::Malformed);}
        let Some(root)=&self.root else {
            return Ok(AbsentProof{queried_key:key.to_vec(),reached:None});
        };
        let kh=key_hash(key)?;
        match root.reached(&kh){
            Node::Leaf{key:existing,..} if existing==key=>{
                Err(Failure::EvidenceMismatch)
            },
            Node::Leaf{key:existing,..}=>{
                let proof=self.membership(existing)?;
                let result=AbsentProof{queried_key:key.to_vec(),reached:Some(proof)};
                result.verify(&self.root())?;
                Ok(result)
            },
            Node::Branch{..}=>Err(Failure::Malformed),
        }
    }
    pub fn from_records(records:impl IntoIterator<Item=(Vec<u8>,Vec<u8>)>)->Result<Self>{
        let mut map=Self::new();
        for (key,value) in records {map.upsert(key,value)?;}
        Ok(map)
    }
}

const TICKET_VERSION:u8=2;
const MAX_PACKET_BYTES:usize=65_536; // private no-WASI byte buffer
// v2 authenticated-state proof representation; intentionally not the v1 ABI.
impl MemberProof {
    pub fn encode(&self,out:&mut Vec<u8>)->Result<()>{
        if !valid_key(&self.key)||self.key.len()>u8::MAX as usize ||
           self.value.len()>MAX_VALUE || self.count==0 ||
           self.count>MAX_ITEMS as u64 || self.path.len()>256 {
            return Err(Failure::Malformed);
        }
        out.extend(self.count.to_le_bytes());
        out.push(self.key.len() as u8);
        out.extend(&self.key);
        out.extend(checked_size(self.value.len())?);
        out.extend(&self.value);
        out.extend((self.path.len() as u16).to_le_bytes());
        let mut last=None;
        for step in &self.path{
            if step.bit>=256 || last.is_some_and(|previous|step.bit<=previous){
                return Err(Failure::Malformed);
            }
            last=Some(step.bit);
            out.extend(step.bit.to_le_bytes());
            out.extend(step.sibling);
        }
        Ok(())
    }
    pub(crate) fn decode(r:&mut Reader<'_>)->Result<Self>{
        let count=r.u64()?;
        if count==0 || count>MAX_ITEMS as u64 {return Err(Failure::Malformed);}
        let len=r.byte()? as usize;
        if len>33 {return Err(Failure::Malformed);}
        let key=r.take(len)?.to_vec();
        if !valid_key(&key){return Err(Failure::Malformed);}
        let n=u32::from_le_bytes(r.take(4)?
            .try_into().map_err(|_|Failure::Malformed)?) as usize;
        if n>MAX_VALUE{return Err(Failure::Malformed);}
        let value=r.take(n)?.to_vec();
        let steps=r.u16()? as usize;
        if steps>256{return Err(Failure::Malformed);}
        let mut path=Vec::with_capacity(steps);
        let mut last=None;
        for _ in 0..steps {
            let bit=r.u16()?;
            if bit>=256 || last.is_some_and(|previous|bit<=previous){
                return Err(Failure::Malformed);
            }
            last=Some(bit);
            path.push(PathStep{bit,sibling:r.address()?});
        }
        Ok(Self{key,value,count,path})
    }
}
impl AbsentProof {
    pub fn encode(&self,out:&mut Vec<u8>)->Result<()>{
        if !valid_key(&self.queried_key) {return Err(Failure::Malformed);}
        out.push(self.queried_key.len() as u8);
        out.extend(&self.queried_key);
        match &self.reached{
            None=>out.push(0),
            Some(member)=>{out.push(1);member.encode(out)?;}
        }
        Ok(())
    }
    pub(crate) fn decode(r:&mut Reader<'_>)->Result<Self>{
        let n=r.byte()? as usize;
        if n>33{return Err(Failure::Malformed);}
        let queried_key=r.take(n)?.to_vec();
        if !valid_key(&queried_key){return Err(Failure::Malformed);}
        let reached=match r.byte()? {
            0=>None,
            1=>Some(MemberProof::decode(r)?),
            _=>return Err(Failure::Malformed),
        };
        Ok(Self{queried_key,reached})
    }
}

