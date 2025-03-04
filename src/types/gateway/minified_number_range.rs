use super::payload::Heartbeat;

#[derive(Clone, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct MinifiedNumberRange {
    pub from: u64,
    pub to: u64,
    pub except: Vec<u64>,
}

impl From<&Vec<u64>> for MinifiedNumberRange {
    fn from(value: &Vec<u64>) -> Self {
        todo!()
    }
}

impl From<MinifiedNumberRange> for Heartbeat {
    fn from(value: MinifiedNumberRange) -> Self {
        todo!()
    }
}
