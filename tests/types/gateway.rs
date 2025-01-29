use polyproto::types::gateway::payload::{
    Hello, Identify, ServiceChannel, ServiceChannelAck, ServiceChannelAction,
};
use polyproto::types::gateway::{Event, Opcode, Payload};

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn serde_event_payload_hello() {
    let hello = Event {
        n: "core".to_string(),
        op: Opcode::Hello as u16,
        d: Payload::Hello(Hello {
            heartbeat_interval: 30000,
        }),
        s: None,
    };
    let hello_json = serde_json::to_string(&hello).unwrap();
    let hello_from_json = serde_json::from_str::<Event>(&hello_json).unwrap();
    assert_eq!(hello, hello_from_json);
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
