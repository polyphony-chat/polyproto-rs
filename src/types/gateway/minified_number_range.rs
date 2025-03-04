#[derive(Clone, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct MinifiedNumberRange {
    pub from: u64,
    pub to: u64,
    pub except: Vec<u64>,
}
