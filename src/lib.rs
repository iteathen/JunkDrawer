//! Public minimal test-bench extraction of AlgoX Phase Zero Core dependencies.
//! The original root source was sliced at the end of its Core evaluator;
//! unrelated Ledger/marketplace modules were intentionally not mirrored.
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap,BTreeSet};
pub mod pz_g1;
pub mod incremental_map;
pub mod sponsor_reference;

pub type Address = [u8; 32];
const TX_DOMAIN: &[u8] = b"AlgoX-PhaseZero/transaction\0";
const COMMIT_DOMAIN: &[u8] = b"AlgoX-PhaseZero/commitment\0";
const MAX_TX_BYTES: usize = 65_536;
const MAX_NODES: usize = 1024;
const MAX_DEPTH: usize = 64;
const MAX_JOB_STEPS: u64 = 1_000_000; // Prototype's finite economic job limit, not a language rule.
const MAX_STACK: usize = 256; // Executor resource limit; exceeding it is non-completion.
const MAX_PAYMENT_STEPS: u64 = 4096; // Phase Zero payment evaluator budget, not candidate bound.
const MAX_AWARDS: usize = 8;
const MAX_TIERS: usize = 16;
// Research-only stake exit delay, not a selected production security period.
pub const TRIAL_UNBOND_DELAY: u64 = 64;

// Disposable Phase Zero burden estimator: measured canonical wire length,
// admitted listing lifetime and a fixed cleanup allowance. Not a real-world
// per-node resource monitor, consensus fee parameter, or subsidy controller.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BurdenSchedule {
    pub tx_base: u64,
    pub per_wire_byte: u64,
    pub per_listing_step: u64,
    pub listing_cleanup: u64,
}
// Derived only from authenticated canonical transactions, never from
// individual nodes' privately reported CPU/memory/network usage.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BurdenStats {
    pub charged_transactions: u64,
    pub applied_transactions: u64,
    pub failed_transactions: u64,
    pub signed_wire_bytes: u64,
    pub listings_posted: u64,
    pub fees_collected: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Failure {
    Malformed, Unsupported, Unauthorized, Nonce, InsufficientFunds,
    Unavailable, Expired, Incomplete, EvidenceMismatch, ResourceExhausted,
    ArithmeticTrap, Overflow,
}
impl Failure {
    pub fn code(&self) -> i32 {
        match self {
            Self::Malformed => 1, Self::Unsupported => 2, Self::Unauthorized => 3,
            Self::Nonce => 4, Self::InsufficientFunds => 5, Self::Unavailable => 6,
            Self::Expired => 7, Self::Incomplete => 8, Self::EvidenceMismatch => 9,
            Self::ResourceExhausted => 10, Self::ArithmeticTrap => 11, Self::Overflow => 12,
        }
    }
}
type Result<T> = std::result::Result<T, Failure>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Node {
    Const(i64), Arg(u8), Add(Box<Node>, Box<Node>), Sub(Box<Node>, Box<Node>),
    Mul(Box<Node>, Box<Node>), Le(Box<Node>, Box<Node>),
    If(Box<Node>, Box<Node>, Box<Node>), Recur(Vec<Node>),
}
impl Node {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Node::Const(v) => { out.push(0); out.extend(v.to_le_bytes()); }
            Node::Arg(i) => { out.extend([1, *i]); }
            Node::Add(a,b) => { out.push(2); a.encode(out); b.encode(out); }
            Node::Sub(a,b) => { out.push(3); a.encode(out); b.encode(out); }
            Node::Mul(a,b) => { out.push(4); a.encode(out); b.encode(out); }
            Node::Le(a,b) => { out.push(5); a.encode(out); b.encode(out); }
            Node::If(a,b,c) => { out.push(6); a.encode(out); b.encode(out); c.encode(out); }
            Node::Recur(args) => { out.push(7); for a in args { a.encode(out); } }
        }
    }
    fn check(&self, arity: u8, depth: usize, count: &mut usize) -> Result<()> {
        if depth > MAX_DEPTH { return Err(Failure::Malformed); }
        *count += 1;
        if *count > MAX_NODES { return Err(Failure::Malformed); }
        match self {
            Node::Const(_) => Ok(()),
            Node::Arg(i) if *i < arity => Ok(()),
            Node::Arg(_) => Err(Failure::Malformed),
            Node::Add(a,b) | Node::Sub(a,b) | Node::Mul(a,b) | Node::Le(a,b) => {
                a.check(arity, depth + 1, count)?;
                b.check(arity, depth + 1, count)
            }
            Node::If(a,b,c) => {
                a.check(arity, depth + 1, count)?;
                b.check(arity, depth + 1, count)?;
                c.check(arity, depth + 1, count)
            }
            Node::Recur(args) if args.len() == arity as usize => {
                for a in args { a.check(arity, depth + 1, count)?; }
                Ok(())
            }
            Node::Recur(_) => Err(Failure::Malformed),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Program { pub arity: u8, pub body: Node }
impl Program {
    pub fn validate(&self) -> Result<()> {
        if self.arity > 8 { return Err(Failure::Malformed); }
        self.body.check(self.arity, 0, &mut 0)
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![self.arity];
        self.body.encode(&mut out);
        out
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Problem {
    pub baseline: Program, pub cases: Vec<Vec<i64>>,
    pub costs: [u64; 8], pub min_saving: u64,
    pub reveal_window: u64, pub verification_window: u64,
}
impl Problem {
    pub fn validate(&self) -> Result<()> {
        self.baseline.validate()?;
        if self.cases.is_empty() || self.cases.len() > 64 || self.reveal_window == 0 ||
            self.verification_window <= self.reveal_window ||
            self.cases.iter().any(|v| v.len() != self.baseline.arity as usize) {
            return Err(Failure::Malformed);
        }
        Ok(())
    }
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend(self.baseline.encode());
        out.push(self.cases.len() as u8);
        for row in &self.cases { for item in row { out.extend(item.to_le_bytes()); } }
        for cost in self.costs { out.extend(cost.to_le_bytes()); }
        out.extend(self.min_saving.to_le_bytes());
        out.extend(self.reveal_window.to_le_bytes());
        out.extend(self.verification_window.to_le_bytes());
    }
}

struct Reader<'a> { data: &'a [u8], i: usize, nodes: usize }
impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self { Self { data, i: 0, nodes: 0 } }
    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self.i.checked_add(count).ok_or(Failure::Malformed)?;
        if end > self.data.len() { return Err(Failure::Malformed); }
        let bytes = &self.data[self.i..end]; self.i = end; Ok(bytes)
    }
    fn byte(&mut self) -> Result<u8> { Ok(self.take(1)?[0]) }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().map_err(|_| Failure::Malformed)?))
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().map_err(|_| Failure::Malformed)?))
    }
    fn i64(&mut self) -> Result<i64> {
        Ok(i64::from_le_bytes(self.take(8)?.try_into().map_err(|_| Failure::Malformed)?))
    }
    fn address(&mut self) -> Result<Address> {
        self.take(32)?.try_into().map_err(|_| Failure::Malformed)
    }
    fn finished(&self) -> Result<()> {
        if self.i != self.data.len() { Err(Failure::Malformed) } else { Ok(()) }
    }
    fn node(&mut self, arity: u8, depth: usize) -> Result<Node> {
        self.nodes += 1;
        if depth > MAX_DEPTH || self.nodes > MAX_NODES { return Err(Failure::Malformed); }
        Ok(match self.byte()? {
            0 => Node::Const(self.i64()?),
            1 => { let idx = self.byte()?; if idx >= arity { return Err(Failure::Malformed); } Node::Arg(idx) },
            2 => Node::Add(Box::new(self.node(arity,depth+1)?), Box::new(self.node(arity,depth+1)?)),
            3 => Node::Sub(Box::new(self.node(arity,depth+1)?), Box::new(self.node(arity,depth+1)?)),
            4 => Node::Mul(Box::new(self.node(arity,depth+1)?), Box::new(self.node(arity,depth+1)?)),
            5 => Node::Le(Box::new(self.node(arity,depth+1)?), Box::new(self.node(arity,depth+1)?)),
            6 => Node::If(Box::new(self.node(arity,depth+1)?), Box::new(self.node(arity,depth+1)?), Box::new(self.node(arity,depth+1)?)),
            7 => { let mut a=Vec::new(); for _ in 0..arity { a.push(self.node(arity,depth+1)?); } Node::Recur(a) },
            _ => return Err(Failure::Unsupported),
        })
    }
    fn program(&mut self) -> Result<Program> {
        let arity = self.byte()?;
        if arity > 8 { return Err(Failure::Malformed); }
        self.nodes = 0;
        Ok(Program { arity, body: self.node(arity,0)? })
    }
    fn payment_plan(&mut self) -> Result<PaymentPlan> {
        let count = self.byte()? as usize;
        if count == 0 || count > MAX_AWARDS { return Err(Failure::Malformed); }
        let mut slots = Vec::with_capacity(count);
        for _ in 0..count {
            let min_bps = self.u16()?;
            let ceiling = self.u64()?;
            let amount = match self.byte()? {
                0 => AmountRule::Fixed(self.u64()?),
                1 => {
                    let count = self.byte()? as usize;
                    if count == 0 || count > MAX_TIERS { return Err(Failure::Malformed); }
                    let mut tiers = Vec::with_capacity(count);
                    for _ in 0..count {
                        tiers.push(Tier { min_bps: self.u16()?, amount: self.u64()? });
                    }
                    AmountRule::Table(tiers)
                }
                2 => AmountRule::Formula(self.program()?),
                _ => return Err(Failure::Unsupported),
            };
            slots.push(PaymentSlot { min_bps, ceiling, amount });
        }
        let plan = PaymentPlan { slots };
        plan.validate()?;
        Ok(plan)
    }
    fn bound_test(&mut self)->Result<BoundTest>{
        if self.data.get(self.i)==Some(&0xff) {
            self.byte()?;
            let len=self.u16()? as usize;
            if len==0 || len>8192{return Err(Failure::ResourceExhausted);}
            let references=sponsor_reference::SponsorReferences::decode(self.take(len)?)?;
            let test=BoundTest::Reference{references,
                reveal_window:self.u64()?,verification_window:self.u64()?};
            test.validate()?;Ok(test)
        } else {Ok(BoundTest::Legacy(self.problem()?))}
    }
    fn problem(&mut self) -> Result<Problem> {
        let baseline = self.program()?;
        let count = self.byte()? as usize;
        if count == 0 || count > 64 { return Err(Failure::Malformed); }
        let mut cases = Vec::with_capacity(count);
        for _ in 0..count {
            let mut row = Vec::new();
            for _ in 0..baseline.arity { row.push(self.i64()?); }
            cases.push(row);
        }
        let mut costs = [0; 8];
        for x in &mut costs { *x = self.u64()?; }
        let problem = Problem { baseline, cases, costs,
            min_saving: self.u64()?, reveal_window: self.u64()?, verification_window: self.u64()? };
        problem.validate()?;
        Ok(problem)
    }
}

/// The immutable sponsor test retains exact legacy Problem bytes.
/// A 0xff discriminant cannot collide with legacy Core arities 0..=8.
#[derive(Clone,Debug,PartialEq,Eq)]
pub enum BoundTest {
    Legacy(Problem),
    Reference{
        references:sponsor_reference::SponsorReferences,
        reveal_window:u64,verification_window:u64,
    }
}
impl BoundTest {
    pub fn validate(&self)->Result<()>{
        match self {
            Self::Legacy(p)=>p.validate(),
            Self::Reference{references,reveal_window,verification_window}=>{
                references.validate()?;
                if *reveal_window==0 || *verification_window<=*reveal_window{
                    return Err(Failure::Malformed);
                }
                Ok(())
            }
        }
    }
    pub fn arity(&self)->u8{
        match self {
            Self::Legacy(p)=>p.baseline.arity,
            Self::Reference{references,..}=>references.arity
        }
    }
    pub fn windows(&self)->(u64,u64){
        match self{
            Self::Legacy(p)=>(p.reveal_window,p.verification_window),
            Self::Reference{reveal_window,verification_window,..}=>
                (*reveal_window,*verification_window)
        }
    }
    pub fn encode(&self,out:&mut Vec<u8>){
        match self{
            Self::Legacy(p)=>p.encode(out),
            Self::Reference{references,reveal_window,verification_window}=>{
                let bytes=references.raw_encode();
                out.push(0xff);
                out.extend((bytes.len() as u16).to_le_bytes());
                out.extend(bytes);
                out.extend(reveal_window.to_le_bytes());
                out.extend(verification_window.to_le_bytes());
            }
        }
    }
    pub fn evaluate(&self,candidate:&Program,budget:u64)->Result<Evidence>{
        match self{
            Self::Legacy(p)=>evaluate(p,candidate,budget),
            Self::Reference{references,..}=>references.evaluate(candidate,budget)
        }
    }
}

pub fn commitment(candidate: &Program, salt: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(COMMIT_DOMAIN);
    hasher.update(salt);
    hasher.update(candidate.encode());
    hasher.finalize().into()
}

// One semantic entitlement model, with three equivalent amount representations.
// Every independently awarded slot has a fully reserved ceiling, one winning claim,
// and the same canonical first-qualifying-commitment ordering.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tier { pub min_bps: u16, pub amount: u64 }
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AmountRule {
    Fixed(u64),
    Table(Vec<Tier>), // highest eligible threshold wins; tiers do not accumulate
    Formula(Program), // existing Core, evaluated over [baseline_cost,candidate_cost]
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentSlot {
    pub min_bps: u16, pub ceiling: u64, pub amount: AmountRule,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentPlan { pub slots: Vec<PaymentSlot> }
impl PaymentPlan {
    pub fn fixed(amount: u64) -> Self {
        Self { slots: vec![PaymentSlot { min_bps: 0, ceiling: amount,
            amount: AmountRule::Fixed(amount) }] }
    }
    pub fn validate(&self) -> Result<u64> {
        if self.slots.is_empty() || self.slots.len() > MAX_AWARDS {
            return Err(Failure::Malformed);
        }
        let mut escrow = 0u64;
        for slot in &self.slots {
            if slot.min_bps > 10_000 { return Err(Failure::Malformed); }
            escrow = escrow.checked_add(slot.ceiling).ok_or(Failure::Overflow)?;
            match &slot.amount {
                AmountRule::Fixed(value) if *value <= slot.ceiling => {},
                AmountRule::Fixed(_) => return Err(Failure::Malformed),
                AmountRule::Table(tiers) => {
                    if tiers.is_empty() || tiers.len() > MAX_TIERS { return Err(Failure::Malformed); }
                    let mut previous = None;
                    for tier in tiers {
                        if tier.min_bps > 10_000 || tier.amount > slot.ceiling ||
                            previous.is_some_and(|x| tier.min_bps <= x) { return Err(Failure::Malformed); }
                        previous = Some(tier.min_bps);
                    }
                }
                AmountRule::Formula(program) => {
                    program.validate()?;
                    if program.arity != 2 { return Err(Failure::Malformed); }
                }
            }
        }
        Ok(escrow)
    }
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.slots.len() as u8);
        for slot in &self.slots {
            out.extend(slot.min_bps.to_le_bytes());
            out.extend(slot.ceiling.to_le_bytes());
            match &slot.amount {
                AmountRule::Fixed(value) => { out.push(0); out.extend(value.to_le_bytes()); }
                AmountRule::Table(tiers) => {
                    out.push(1); out.push(tiers.len() as u8);
                    for tier in tiers {
                        out.extend(tier.min_bps.to_le_bytes());
                        out.extend(tier.amount.to_le_bytes());
                    }
                }
                AmountRule::Formula(program) => { out.push(2); out.extend(program.encode()); }
            }
        }
    }
    // Verified sponsor cost units are distinct from Wasmtime fuel and network fees.
    pub fn entitlements(&self, evidence: &Evidence) -> Result<Vec<u64>> {
        if !evidence.accepted { return Ok(vec![0; self.slots.len()]); }
        let base = evidence.baseline_cost;
        let candidate = evidence.candidate_cost;
        let bps: u16 = if base == 0 || candidate >= base { 0 }
            else { ((u128::from(base-candidate)*10_000)/u128::from(base)) as u16 };
        let mut result = Vec::with_capacity(self.slots.len());
        for slot in &self.slots {
            if bps < slot.min_bps { result.push(0); continue; }
            let amount = match &slot.amount {
                AmountRule::Fixed(value) => *value,
                AmountRule::Table(tiers) => tiers.iter().rev()
                    .find(|tier| bps >= tier.min_bps).map_or(0,|tier|tier.amount),
                AmountRule::Formula(program) => {
                    let inputs = [i64::try_from(base).map_err(|_| Failure::Overflow)?,
                                  i64::try_from(candidate).map_err(|_| Failure::Overflow)?];
                    let costs = [0u64;8];
                    let mut meter = Meter { costs:&costs, steps:0, limit:MAX_PAYMENT_STEPS, cost:0 };
                    let amount = eval(&program.body,program,&inputs,&mut meter,0)?;
                    u64::try_from(amount).map_err(|_| Failure::ArithmeticTrap)?
                }
            };
            result.push(amount.min(slot.ceiling));
        }
        Ok(result)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evidence {
    pub accepted: bool, pub baseline_cost: u64, pub candidate_cost: u64,
    pub transcript: [u8;32],
}
impl Evidence {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![u8::from(self.accepted)];
        out.extend(self.baseline_cost.to_le_bytes());
        out.extend(self.candidate_cost.to_le_bytes());
        out.extend(self.transcript);
        out
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        let flag = r.byte()?;
        if flag > 1 { return Err(Failure::Malformed); }
        Ok(Self { accepted: flag == 1, baseline_cost: r.u64()?,
            candidate_cost: r.u64()?, transcript: r.address()? })
    }
}
struct Meter<'a> { costs: &'a [u64;8], steps: u64, limit: u64, cost: u64 }
impl<'a> Meter<'a> {
    fn charge(&mut self, op: usize) -> Result<()> {
        self.steps = self.steps.checked_add(1).ok_or(Failure::ResourceExhausted)?;
        if self.steps > self.limit { return Err(Failure::ResourceExhausted); }
        self.cost = self.cost.checked_add(self.costs[op]).ok_or(Failure::Overflow)?;
        Ok(())
    }
}
fn eval(node: &Node, program: &Program, frame: &[i64], meter: &mut Meter<'_>, depth: usize) -> Result<i64> {
    let op = match node { Node::Const(_) => 0, Node::Arg(_) => 1, Node::Add(..) => 2,
        Node::Sub(..) => 3, Node::Mul(..) => 4, Node::Le(..) => 5,
        Node::If(..) => 6, Node::Recur(..) => 7 };
    meter.charge(op)?;
    if depth >= MAX_STACK { return Err(Failure::ResourceExhausted); }
    Ok(match node {
        Node::Const(v) => *v,
        Node::Arg(i) => *frame.get(*i as usize).ok_or(Failure::Malformed)?,
        Node::Add(a,b) => eval(a,program,frame,meter,depth)?.checked_add(eval(b,program,frame,meter,depth)?).ok_or(Failure::ArithmeticTrap)?,
        Node::Sub(a,b) => eval(a,program,frame,meter,depth)?.checked_sub(eval(b,program,frame,meter,depth)?).ok_or(Failure::ArithmeticTrap)?,
        Node::Mul(a,b) => eval(a,program,frame,meter,depth)?.checked_mul(eval(b,program,frame,meter,depth)?).ok_or(Failure::ArithmeticTrap)?,
        Node::Le(a,b) => i64::from(eval(a,program,frame,meter,depth)? <= eval(b,program,frame,meter,depth)?),
        Node::If(cond,yes,no) => {
            if eval(cond,program,frame,meter,depth)? != 0 {
                eval(yes,program,frame,meter,depth)
            } else { eval(no,program,frame,meter,depth) }?
        }
        Node::Recur(args) => {
            let mut next = Vec::with_capacity(args.len());
            for a in args { next.push(eval(a,program,frame,meter,depth)?); }
            eval(&program.body,program,&next,meter,depth+1)?
        }
    })
}
pub fn evaluate(problem: &Problem, candidate: &Program, step_budget: u64) -> Result<Evidence> {
    problem.validate()?; candidate.validate()?;
    if candidate.arity != problem.baseline.arity { return Err(Failure::Malformed); }
    if step_budget == 0 || step_budget > MAX_JOB_STEPS { return Err(Failure::Malformed); }
    let mut meter = Meter { costs: &problem.costs, steps: 0, limit: step_budget, cost: 0 };
    let mut base_total = 0u64;
    let mut candidate_total = 0u64;
    let mut equal = true;
    let mut digest = Sha256::new();
    for row in &problem.cases {
        let base_before = meter.cost;
        let base = eval(&problem.baseline.body,&problem.baseline,row,&mut meter,0)?;
        let base_cost = meter.cost - base_before;
        let cand_before = meter.cost;
        // A candidate trap is a completed failure on this sponsor's finite test.
        let candidate_result = eval(&candidate.body,candidate,row,&mut meter,0);
        if candidate_result == Err(Failure::ResourceExhausted) { return Err(Failure::ResourceExhausted); }
        let value = match candidate_result {
            Ok(v) => v,
            Err(Failure::ArithmeticTrap) => { equal = false; i64::MIN },
            Err(e) => return Err(e),
        };
        let cand_cost = meter.cost - cand_before;
        if value != base { equal = false; }
        base_total = base_total.checked_add(base_cost).ok_or(Failure::Overflow)?;
        candidate_total = candidate_total.checked_add(cand_cost).ok_or(Failure::Overflow)?;
        for arg in row { digest.update(arg.to_le_bytes()); }
        digest.update(base.to_le_bytes());
        digest.update(value.to_le_bytes());
        digest.update(base_cost.to_le_bytes());
        digest.update(cand_cost.to_le_bytes());
    }
    let accepted = equal && base_total >= candidate_total &&
        base_total - candidate_total >= problem.min_saving;
    Ok(Evidence { accepted, baseline_cost: base_total,
        candidate_cost: candidate_total, transcript: digest.finalize().into() })
}

