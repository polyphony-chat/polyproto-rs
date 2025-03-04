use super::payload::Heartbeat;

#[derive(Clone, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct MinifiedNumberRange {
    pub from: u64,
    pub to: u64,
    pub except: Vec<u64>,
}

impl From<&Vec<u64>> for MinifiedNumberRange {
    fn from(value: &Vec<u64>) -> Self {
        if value.is_empty() {
            return Self {
                from: 0,
                to: 0,
                except: Vec::new(),
            };
        }
        if value.len() == 1 {
            return Self {
                from: value[0],
                to: value[0],
                except: Vec::new(),
            };
        }
        let mut min = 0;
        let mut max = 0;
        for item in value.iter() {
            if *item < min {
                min = *item;
            } else if *item > max {
                max = *item
            }
        }
        let mut ordered_values = value.clone();
        ordered_values.sort();

        let mut prev = None;
        let mut next = 0u64;
        let mut missing = Vec::<u64>::new();

        for value in ordered_values.iter() {
            if prev.is_none() {
                prev = Some(*value);
            } else {
                next = *value;
            }

            let some_prev = prev.unwrap();

            if next - some_prev > 1 {
                let mut difference = next - some_prev;
                while difference != 0 {
                    missing.push(difference);
                    difference -= 1;
                }
            }

            prev = Some(next);
        }

        MinifiedNumberRange {
            from: min,
            to: max,
            except: missing,
        }
    }
}

impl From<MinifiedNumberRange> for Heartbeat {
    fn from(value: MinifiedNumberRange) -> Self {
        todo!()
    }
}
