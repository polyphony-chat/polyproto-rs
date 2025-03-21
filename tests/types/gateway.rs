use polyproto::types::gateway::payload::{
    ActorCertificateInvalidation, Heartbeat, HeartbeatAck, Hello, Identify, NewSession, Resume,
    Resumed, ServerCertificateChange, ServiceChannel, ServiceChannelAck, ServiceChannelAction,
};
use polyproto::types::gateway::{Event, Opcode, Payload};
use serde_json::json;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn serde_event() {
    let event = Event {
        n: "core".to_string(),
        op: 3_u16,
        d: Payload::Hello(Hello {
            heartbeat_interval: 0,
            active_migration: None,
        }),
        s: Some(12),
    };
    let mut json = json!(event);
    assert!(json["op"].take().is_string());
    assert!(json["s"].take().is_string());
    assert!(json["n"].take().is_string());
    assert!(json["d"].take().is_object());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn serde_event_payload_hello() {
    let hello = Event {
        n: "core".to_string(),
        op: Opcode::Hello as u16,
        d: Payload::Hello(Hello {
            heartbeat_interval: 30000,
            active_migration: None,
        }),
        s: Some(1),
    };
    let mut json = json!(hello);
    dbg!(&json);
    let hello_json = serde_json::to_string(&hello).unwrap();
    dbg!(&hello_json);
    let hello_from_json = serde_json::from_str::<Event>(&hello_json).unwrap();
    assert_eq!(hello, hello_from_json);
    let mut d = json["d"].take();
    dbg!(&d);
    assert!(d.is_object());
    assert!(dbg!(&d["heartbeatInterval"].take()).is_string());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn serde_event_payload_identify() {
    let identify = Event {
        n: "core".to_string(),
        op: Opcode::Identify as u16,
        d: Payload::Identify(Identify {
            token: "token".to_string(),
        }),
        s: None,
    };
    let identify_json = serde_json::to_string(&identify).unwrap();
    let identify_from_json = serde_json::from_str::<Event>(&identify_json).unwrap();
    assert_eq!(identify, identify_from_json);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn serde_event_payload_service() {
    let mut service = Event {
        n: "core".to_string(),
        op: Opcode::ServiceChannel as u16,
        d: Payload::ServiceChannel(ServiceChannel {
            action: ServiceChannelAction::Subscribe,
            service: "service".to_string(),
        }),
        s: None,
    };
    let service_json = serde_json::to_string(&service).unwrap();
    let service_from_json = serde_json::from_str::<Event>(&service_json).unwrap();
    assert_eq!(service, service_from_json);
    service.d = Payload::ServiceChannel(ServiceChannel {
        action: ServiceChannelAction::Unsubscribe,
        service: "service".to_string(),
    });
    let service_unsub_json = serde_json::to_string(&service).unwrap();
    let service_unsub_from_json = serde_json::from_str::<Event>(&service_unsub_json).unwrap();
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
    let mut service_channel_ack = Event {
        n: "core".to_string(),
        op: Opcode::ServiceChannelAck as u16,
        d: payload.clone(),
        s: Some(1),
    };
    let service_channel_ack_json = serde_json::to_string(&service_channel_ack).unwrap();
    let service_channel_ack_from_json =
        serde_json::from_str::<Event>(&service_channel_ack_json).unwrap();
    assert_eq!(service_channel_ack, service_channel_ack_from_json);
    payload_inner.action = ServiceChannelAction::Unsubscribe;
    payload = Payload::ServiceChannelAck(payload_inner.clone());
    service_channel_ack.d = payload;
    let service_channel_ack_json = serde_json::to_string(&service_channel_ack).unwrap();
    let service_channel_ack_from_json =
        serde_json::from_str::<Event>(&service_channel_ack_json).unwrap();
    assert_eq!(service_channel_ack, service_channel_ack_from_json);
    payload_inner.success = false;
    payload_inner.error = Some("Failure".to_string());
    payload = Payload::ServiceChannelAck(payload_inner.clone());
    service_channel_ack.d = payload;
    let service_channel_ack_json = serde_json::to_string(&service_channel_ack).unwrap();
    let service_channel_ack_from_json =
        serde_json::from_str::<Event>(&service_channel_ack_json).unwrap();
    assert_eq!(service_channel_ack, service_channel_ack_from_json);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn serde_event_payload_new_session() {
    let new_session = Event {
        n: "core".to_string(),
        op: Opcode::NewSession as u16,
        d: Payload::NewSession(NewSession {
            cert: "cert".to_string(),
        }),
        s: Some(10),
    };
    let new_session_json = serde_json::to_string(&new_session).unwrap();
    let new_session_from_json = serde_json::from_str::<Event>(&new_session_json).unwrap();
    assert_eq!(new_session, new_session_from_json);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn serde_event_payload_actor_certificate_invalidation() {
    let actor_certificate_invalidation = Event {
        n: "core".to_string(),
        op: Opcode::ActorCertificateInvalidation as u16,
        d: Payload::ActorCertificateInvalidation(ActorCertificateInvalidation {
            serial: 234789,
            invalid_since: 8923404,
            signature: "signature".to_string(),
        }),
        s: Some(1),
    };
    let actor_certificate_invalidation_json =
        serde_json::to_string(&actor_certificate_invalidation).unwrap();
    let actor_certificate_invalidation_from_json =
        serde_json::from_str::<Event>(&actor_certificate_invalidation_json).unwrap();
    assert_eq!(
        actor_certificate_invalidation,
        actor_certificate_invalidation_from_json
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn serde_event_payload_resume() {
    let resume = Event {
        n: "core".to_string(),
        op: Opcode::Resume as u16,
        d: Payload::Resume(Resume { s: 12 }),
        s: None,
    };
    let resume_json = serde_json::to_string(&resume).unwrap();
    let resume_from_json = serde_json::from_str::<Event>(&resume_json).unwrap();
    assert_eq!(resume, resume_from_json);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn serde_event_payload_resumed() {
    let resumed = Event {
        n: "core".to_string(),
        op: Opcode::Resumed as u16,
        d: Payload::Resumed(Resumed { inner: Vec::new() }),
        s: None,
    };
    let resumed_json = serde_json::to_string(&resumed).unwrap();
    let resumed_from_json = serde_json::from_str::<Event>(&resumed_json).unwrap();
    assert_eq!(resumed, resumed_from_json);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn serde_event_payload_server_certificate_change() {
    let certificate_change = Event {
        n: "core".to_string(),
        op: Opcode::ServerCertificateChange as u16,
        d: Payload::ServerCertificateChange(ServerCertificateChange {
            cert: "cert".to_string(),
            old_invalid_since: 982314122,
        }),
        s: None,
    };
    let certificate_change_json = serde_json::to_string(&certificate_change).unwrap();
    dbg!(&certificate_change_json);
    let certificate_change_from_json =
        serde_json::from_str::<Event>(&certificate_change_json).unwrap();
    assert_eq!(certificate_change, certificate_change_from_json);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn serde_event_payload_server_heartbeat() {
    let event = Event {
        n: "core".to_string(),
        op: Opcode::Heartbeat as u16,
        d: Payload::Heartbeat(Heartbeat {
            from: 0,
            to: 100,
            except: [2, 4, 6, 7, 8].to_vec(),
        }),
        s: None,
    };
    let event_json = serde_json::to_string(&event).unwrap();
    dbg!(&event_json);
    let event_from_json = serde_json::from_str::<Event>(&event_json).unwrap();
    assert_eq!(event, event_from_json);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn serde_event_payload_server_heartbeat_ack() {
    let event = Event {
        n: "core".to_string(),
        op: Opcode::HeartbeatAck as u16,
        d: Payload::HeartbeatAck(HeartbeatAck { inner: [].to_vec() }),
        s: None,
    };
    let event_json = serde_json::to_string(&event).unwrap();
    let event_from_json = serde_json::from_str::<Event>(&event_json).unwrap();
    assert_eq!(event, event_from_json);
}
