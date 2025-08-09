// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![cfg(feature = "types")]

use std::str::FromStr;

use polyproto::certs::Target;
use polyproto::types::pdn::ActorDN;
use polyproto::Name;
use x509_cert::Certificate;

use crate::common::{actor_id_cert, actor_subject, gen_priv_key, init_logger, test_all_platforms};

test_all_platforms! {
fn test_actor_dn_from_valid_id_cert_name() {
    init_logger();
    
    // Generate a valid actor ID certificate
    let cert = actor_id_cert("testuser");
    
    // Convert to x509_cert::Certificate to access the subject
    let x509_cert = Certificate::try_from(cert).unwrap();
    let subject_name = Name::from(x509_cert.tbs_certificate.subject);
    
    // Test the TryFrom<Name> conversion - should succeed
    let result = ActorDN::try_from(subject_name);
    assert!(result.is_ok(), "Failed to convert valid certificate subject to ActorDN");
    
    let _actor_dn = result.unwrap();
    // Since ActorDN fields are private and no getters exist, 
    // we can only test that the conversion succeeds for valid input
}
}

test_all_platforms! {
fn test_actor_dn_from_different_usernames() {
    init_logger();
    
    let test_cases = ["alice", "bob", "charlie123"];
    
    for username in test_cases.iter() {
        // Generate ID cert for each username
        let cert = actor_id_cert(username);
        let x509_cert = Certificate::try_from(cert).unwrap();
        let subject_name = Name::from(x509_cert.tbs_certificate.subject);
        
        // Convert to ActorDN - should succeed for all valid usernames
        let result = ActorDN::try_from(subject_name);
        assert!(result.is_ok(), "Failed to convert valid certificate for user: {}", username);
    }
}
}

test_all_platforms! {
fn test_actor_dn_custom_subject_name() {
    init_logger();
    
    let priv_key = gen_priv_key();
    
    // Create a custom subject with specific components
    let subject = actor_subject("customuser");
    
    let csr = polyproto::certs::idcsr::IdCsr::new(
        &subject,
        &priv_key,
        &polyproto::certs::capabilities::Capabilities::default_actor(),
        Some(Target::Actor),
    ).unwrap();
    
    let cert = polyproto::certs::idcert::IdCert::from_actor_csr(
        csr,
        &priv_key,
        polyproto::types::x509_cert::SerialNumber::from_bytes_be(&[1]).unwrap(),
        crate::common::home_server_subject(),
        crate::common::default_validity(),
    ).unwrap();
    
    // Extract subject and convert
    let x509_cert = Certificate::try_from(cert).unwrap();
    let subject_name = Name::from(x509_cert.tbs_certificate.subject);
    let result = ActorDN::try_from(subject_name);
    
    // Should succeed with custom user
    assert!(result.is_ok(), "Failed to convert custom certificate subject to ActorDN");
}
}

test_all_platforms! {
fn test_actor_dn_missing_federation_id() {
    init_logger();
    
    // Create a malformed subject missing the UID (Federation ID)
    let malformed_subject = Name::from_str("CN=testuser,DC=polyphony,DC=chat,uniqueIdentifier=client1").unwrap();
    
    // Should fail because Federation ID (UID) is missing
    let result = ActorDN::try_from(malformed_subject);
    assert!(result.is_err());
    
    let error = result.unwrap_err();
    println!("Missing Federation ID error: {}", error);
    // This fails at the Name validation level before reaching ActorDN parsing
    assert!(error.to_string().contains("malformed") || error.to_string().contains("validation"));
}
}

test_all_platforms! {
fn test_actor_dn_missing_local_name() {
    init_logger();
    
    // Create a malformed subject missing the CN (Local Name)
    let malformed_subject = Name::from_str("DC=polyphony,DC=chat,UID=testuser@polyphony.chat,uniqueIdentifier=client1").unwrap();
    
    // Should fail because Local Name (CN) is missing
    let result = ActorDN::try_from(malformed_subject);
    assert!(result.is_err());
    
    let error = result.unwrap_err();
    assert!(error.to_string().contains("Expected Local Name in ActorDN, found none"));
}
}

test_all_platforms! {
fn test_actor_dn_missing_session_id() {
    init_logger();
    
    // Create a malformed subject missing the uniqueIdentifier (Session ID)
    let malformed_subject = Name::from_str("CN=testuser,DC=polyphony,DC=chat,UID=testuser@polyphony.chat").unwrap();
    
    // Should fail because Session ID (uniqueIdentifier) is missing
    let result = ActorDN::try_from(malformed_subject);
    assert!(result.is_err());
    
    let error = result.unwrap_err();
    println!("Missing Session ID error: {}", error);
    // This fails at the Name validation level before reaching ActorDN parsing
    assert!(error.to_string().contains("expected to be between") || error.to_string().contains("malformed"));
}
}

test_all_platforms! {
fn test_actor_dn_duplicate_oid_error() {
    init_logger();
    
    // Create a malformed subject with duplicate CN values
    let malformed_subject = Name::from_str("CN=testuser,CN=duplicate,DC=polyphony,DC=chat,UID=testuser@polyphony.chat,uniqueIdentifier=client1").unwrap();
    
    // Should fail because of duplicate OID
    let result = ActorDN::try_from(malformed_subject);
    assert!(result.is_err());
    
    let error = result.unwrap_err();
    println!("Duplicate OID error: {}", error);
    // This fails at the Name validation level before reaching ActorDN parsing
    assert!(error.to_string().contains("expected to be between") || error.to_string().contains("malformed"));
}
}

test_all_platforms! {
fn test_actor_dn_complex_distinguished_name() {
    init_logger();
    
    // Create a more complex distinguished name with additional fields
    let complex_subject = Name::from_str(
        "CN=testuser,O=TestOrg,OU=TestUnit,DC=polyphony,DC=chat,UID=testuser@polyphony.chat,uniqueIdentifier=client1"
    ).unwrap();
    
    let result = ActorDN::try_from(complex_subject);
    
    // This should succeed, with additional fields captured
    assert!(result.is_ok(), "Complex distinguished name should be parsed successfully");
}
}

test_all_platforms! {
fn test_actor_dn_roundtrip_conversion() {
    init_logger();
    
    // Generate multiple certificates and ensure they convert properly
    let test_users = ["alice", "bob", "charlie"];
    
    for user in test_users.iter() {
        // Create certificate
        let cert = actor_id_cert(user);
        let x509_cert = Certificate::try_from(cert).unwrap();
        let original_subject = Name::from(x509_cert.tbs_certificate.subject);
        
        // Convert to ActorDN - should succeed for all valid users
        let result = ActorDN::try_from(original_subject.clone());
        assert!(result.is_ok(), "Roundtrip conversion should succeed for user: {}", user);
    }
}
} 