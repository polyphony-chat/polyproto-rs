// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::ops::{Deref, DerefMut};

use der::asn1::Ia5String;
use der::Length;

use crate::errors::base::ConstraintError;
use crate::errors::composite::ConversionError;
use crate::Constrained;

pub struct Challenge {
    challenge: Ia5String,
}

impl std::str::FromStr for Challenge {
    type Err = ConversionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let challenge = Self {
            challenge: Ia5String::new(s)?,
        };
        challenge.validate()?;
        Ok(challenge)
    }
}

impl Deref for Challenge {
    type Target = Ia5String;

    fn deref(&self) -> &Self::Target {
        &self.challenge
    }
}

impl DerefMut for Challenge {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.challenge
    }
}

impl Constrained for Challenge {
    fn validate(&self) -> Result<(), crate::errors::base::ConstraintError> {
        if self.challenge.len() < Length::new(32) {
            return Err(ConstraintError::OutOfBounds {
                lower: 32,
                upper: 256,
                actual: self.challenge.len().to_string(),
                reason: "Challenge string must be at least 32 characters long".to_string(),
            });
        }

        if self.challenge.len() > Length::new(256) {
            return Err(ConstraintError::OutOfBounds {
                lower: 32,
                upper: 256,
                actual: self.challenge.len().to_string(),
                reason: "Challenge string must be at most 256 characters long".to_string(),
            });
        }

        Ok(())
    }
}
