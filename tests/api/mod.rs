// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

pub(crate) mod core;

use polyproto::types::ChallengeString;

#[test]
fn challenge_string_length() {
    let mut thirtytwo = String::from_utf8(vec![121; 32]).unwrap();
    let mut twofivesix = String::from_utf8(vec![121; 256]).unwrap();
    let challenge = ChallengeString::new(thirtytwo.clone(), 1);
    assert!(challenge.is_ok());
    let challenge = ChallengeString::new(twofivesix.clone(), 1);

    assert!(challenge.is_ok());
    thirtytwo.pop().unwrap(); // String is now 31 characters long
    let challenge = ChallengeString::new(thirtytwo, 1);

    assert!(challenge.is_err());
    twofivesix.push('a'); // String is now 256 characters long
    let challenge = ChallengeString::new(twofivesix, 1);

    assert!(challenge.is_err());
}
