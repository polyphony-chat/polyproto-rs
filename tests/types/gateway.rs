// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use log::info;
use polyproto::types::gateway::payload::{
    ActorCertificateInvalidation, Heartbeat, HeartbeatAck, Hello, Identify, NewSession, Resume,
    Resumed, ServerCertificateChange, ServiceChannel, ServiceChannelAck, ServiceChannelAction,
};
use polyproto::types::gateway::{CoreEvent, Payload};
use serde_json::json;

use crate::common;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn serde_event() {
    let event = CoreEvent::new(
        Payload::Hello(Hello {
            heartbeat_interval: 0,
        }),
        Some(12),
    );
    let mut json = json!(event);
    assert!(json["op"].take().is_string());
    assert!(json["s"].take().is_string());
    assert!(json["n"].take().is_string());
    assert!(json["d"].take().is_object());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn serde_event_payload_hello() {
    let hello = CoreEvent::new(
        Payload::Hello(Hello {
            heartbeat_interval: 30000,
        }),
        Some(1),
    );
    let mut json = json!(hello);
    dbg!(&json);
    let hello_json = serde_json::to_string(&hello).unwrap();
    dbg!(&hello_json);
    let hello_from_json = serde_json::from_str::<CoreEvent>(&hello_json).unwrap();
    assert_eq!(hello, hello_from_json);
    let mut d = json["d"].take();
    dbg!(&d);
    assert!(d.is_object());
    assert!(dbg!(&d["heartbeatInterval"].take()).is_string());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn serde_event_payload_identify() {
    let identify = CoreEvent::new(
        Payload::Identify(Identify {
            token: "token".to_string(),
        }),
        None,
    );
    let identify_json = serde_json::to_string(&identify).unwrap();
    let identify_from_json = serde_json::from_str::<CoreEvent>(&identify_json).unwrap();
    assert_eq!(identify, identify_from_json);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn serde_event_payload_service() {
    let service = CoreEvent::new(
        Payload::ServiceChannel(ServiceChannel {
            action: ServiceChannelAction::Subscribe,
            service: "service".to_string(),
        }),
        None,
    );
    let service_json = serde_json::to_string(&service).unwrap();
    let service_from_json = serde_json::from_str::<CoreEvent>(&service_json).unwrap();
    assert_eq!(service, service_from_json);
    let service = CoreEvent::new(
        Payload::ServiceChannel(ServiceChannel {
            action: ServiceChannelAction::Unsubscribe,
            service: "service".to_string(),
        }),
        None,
    );
    let service_unsub_json = serde_json::to_string(&service).unwrap();
    let service_unsub_from_json = serde_json::from_str::<CoreEvent>(&service_unsub_json).unwrap();
    assert_eq!(service, service_unsub_from_json);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn serde_event_payload_service_ack() {
    let mut payload_inner = ServiceChannelAck {
        action: ServiceChannelAction::Subscribe,
        service: "service".to_string(),
        success: true,
        error: None,
    };
    let mut payload = Payload::ServiceChannelAck(payload_inner.clone());
    let mut service_channel_ack = CoreEvent::new(payload.clone(), Some(1));
    let service_channel_ack_json = serde_json::to_string(&service_channel_ack).unwrap();
    let service_channel_ack_from_json =
        serde_json::from_str::<CoreEvent>(&service_channel_ack_json).unwrap();
    assert_eq!(service_channel_ack, service_channel_ack_from_json);

    payload_inner.action = ServiceChannelAction::Unsubscribe;
    payload = Payload::ServiceChannelAck(payload_inner.clone());
    // Reconstruct the CoreEvent with updated payload
    service_channel_ack = CoreEvent::new(payload.clone(), Some(1));
    let service_channel_ack_json = serde_json::to_string(&service_channel_ack).unwrap();
    let service_channel_ack_from_json =
        serde_json::from_str::<CoreEvent>(&service_channel_ack_json).unwrap();
    assert_eq!(service_channel_ack, service_channel_ack_from_json);

    payload_inner.success = false;
    payload_inner.error = Some("Failure".to_string());
    payload = Payload::ServiceChannelAck(payload_inner.clone());
    // Reconstruct the CoreEvent with updated payload
    service_channel_ack = CoreEvent::new(payload.clone(), Some(1));
    let service_channel_ack_json = serde_json::to_string(&service_channel_ack).unwrap();
    let service_channel_ack_from_json =
        serde_json::from_str::<CoreEvent>(&service_channel_ack_json).unwrap();
    assert_eq!(service_channel_ack, service_channel_ack_from_json);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn serde_event_payload_new_session() {
    let new_session = CoreEvent::new(
        Payload::NewSession(NewSession {
            cert: "cert".to_string(),
        }),
        Some(10),
    );
    let new_session_json = serde_json::to_string(&new_session).unwrap();
    let new_session_from_json = serde_json::from_str::<CoreEvent>(&new_session_json).unwrap();
    assert_eq!(new_session, new_session_from_json);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn serde_event_payload_actor_certificate_invalidation() {
    let actor_certificate_invalidation = CoreEvent::new(
        Payload::ActorCertificateInvalidation(ActorCertificateInvalidation {
            serial: 234789,
            invalid_since: 8923404,
            signature: "signature".to_string(),
        }),
        Some(1),
    );
    let actor_certificate_invalidation_json =
        serde_json::to_string(&actor_certificate_invalidation).unwrap();
    let actor_certificate_invalidation_from_json =
        serde_json::from_str::<CoreEvent>(&actor_certificate_invalidation_json).unwrap();
    assert_eq!(
        actor_certificate_invalidation,
        actor_certificate_invalidation_from_json
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn serde_event_payload_resume() {
    let resume = CoreEvent::new(Payload::Resume(Resume { s: 12 }), None);
    let resume_json = serde_json::to_string(&resume).unwrap();
    let resume_from_json = serde_json::from_str::<CoreEvent>(&resume_json).unwrap();
    assert_eq!(resume, resume_from_json);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn serde_event_payload_resumed() {
    common::init_logger();
    let resumed = CoreEvent::new(Payload::Resumed(Resumed { inner: Vec::new() }), None);
    let resumed_json = serde_json::to_string(&resumed).unwrap();
    info!("{resumed_json}");
    let resumed_from_json = serde_json::from_str::<CoreEvent>(&resumed_json).unwrap();
    assert_eq!(resumed, resumed_from_json);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn serde_event_payload_server_certificate_change() {
    let certificate_change = CoreEvent::new(
        Payload::ServerCertificateChange(ServerCertificateChange {
            cert: "cert".to_string(),
            old_invalid_since: 982314122,
        }),
        None,
    );
    let certificate_change_json = serde_json::to_string(&certificate_change).unwrap();
    dbg!(&certificate_change_json);
    let certificate_change_from_json =
        serde_json::from_str::<CoreEvent>(&certificate_change_json).unwrap();
    assert_eq!(certificate_change, certificate_change_from_json);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn serde_event_payload_server_heartbeat() {
    let event = CoreEvent::new(
        Payload::Heartbeat(Heartbeat {
            from: 0,
            to: 100,
            except: [2, 4, 6, 7, 8].to_vec(),
        }),
        None,
    );
    let event_json = serde_json::to_string(&event).unwrap();
    dbg!(&event_json);
    let event_from_json = serde_json::from_str::<CoreEvent>(&event_json).unwrap();
    assert_eq!(event, event_from_json);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn serde_event_payload_server_heartbeat_ack() {
    let event = CoreEvent::new(
        Payload::HeartbeatAck(HeartbeatAck { inner: [].to_vec() }),
        None,
    );
    let event_json = serde_json::to_string(&event).unwrap();
    let event_from_json = serde_json::from_str::<CoreEvent>(&event_json).unwrap();
    assert_eq!(event, event_from_json);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn serde_event_payload_server_request_heartbeat() {
    let event = CoreEvent::new(Payload::RequestHeartbeat, None);
    let event_json = serde_json::to_string(&event).unwrap();
    dbg!(&event_json);
    let event_from_json = serde_json::from_str::<CoreEvent>(&event_json).unwrap();
    dbg!(json!(&event_from_json));
    assert_eq!(event, event_from_json);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn heartbeat_from_sequence_numbers_easy() {
    let sequence = &[1u64, 2, 3, 4, 5, 6, 7];
    let heartbeat = Heartbeat::from_sequence_numbers(sequence);
    assert_eq!(heartbeat.from, 1u64);
    assert_eq!(heartbeat.to, 7u64);
    assert!(heartbeat.except == Vec::<u64>::new());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn heartbeat_from_sequence_numbers_late_min() {
    let sequence = &[8u64, 2, 3, 4, 5, 6, 7, 1];
    let heartbeat = Heartbeat::from_sequence_numbers(sequence);
    assert_eq!(heartbeat.from, 1u64);
    assert_eq!(heartbeat.to, 8u64);
    assert!(heartbeat.except == Vec::<u64>::new());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn heartbeat_from_sequence_numbers_except() {
    let sequence = &[1u64, 2, 3, 4, 5, 7, 8];
    let heartbeat = Heartbeat::from_sequence_numbers(sequence);
    assert_eq!(heartbeat.from, 1u64);
    assert_eq!(heartbeat.to, 8u64);
    assert_eq!(heartbeat.except, vec![6]);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn heartbeat_from_sequence_numbers_very_big_except() {
    let sequence = &[1u64, 2, 3, 4, 5, 100];
    let heartbeat = Heartbeat::from_sequence_numbers(sequence);
    assert_eq!(heartbeat.from, 1u64);
    assert_eq!(heartbeat.to, 100u64);
    let missing: Vec<u64> = (6..=99).collect();
    assert_eq!(heartbeat.except, missing);

    let sequence = &[12u64, 2, 3, 102, 5, 100];
    let heartbeat = Heartbeat::from_sequence_numbers(sequence);
    assert_eq!(heartbeat.from, 2u64);
    assert_eq!(heartbeat.to, 102u64);
    let mut missing: Vec<u64> = (6..=99).collect();
    missing.remove(6);
    missing.push(101);
    missing.push(4);
    missing.sort();
    assert_eq!(heartbeat.except, missing);
}
