#![cfg(target_os = "linux")]
use castle_wall_daemon::business_profile::{signer_service::*,signer_contract::*};
use serde_json::json;
fn header() -> serde_json::Value {json!({"v":1,"protocol":SIGNER_PROTOCOL,"request_id":"a".repeat(32),"activation_id":"b".repeat(32),"lease_id":"c".repeat(32),"role":ROLE_REGISTRY[0].0,"epoch":1,"generation":1,"deadline_boottime_ns":"1","preimage_length":0})}
#[test]
fn exact_frame_roundtrip_and_length_bound() {
    let h=header(); assert!(decode(&encode(&h,&[]).unwrap()).is_ok());
    assert!(decode(&vec![0;SIGNER_FRAME_MAX_BYTES+1]).is_err());
    let mut h=header();h["preimage_length"]=json!(SIGNER_PREIMAGE_MAX_BYTES+1);
    assert!(decode(&encode(&h,&[]).unwrap()).is_err());
    let body=vec![0;SIGNER_PREIMAGE_MAX_BYTES];h["preimage_length"]=json!(body.len());
    assert!(decode(&encode(&h,&body).unwrap()).is_ok());
    let raw=castle_wall_daemon::smb::jcs::encode(&{h["preimage_length"]=json!(body.len()+1);h}).unwrap();
    let oversized=[&(raw.len() as u32).to_be_bytes()[..],raw.as_bytes(),&vec![0;body.len()+1]].concat();
    assert!(decode(&oversized).is_err());
}
#[test]
fn malformed_and_duplicate_headers_refuse() {
    let mut h=header(); h["factor"]=json!("sentinel");assert!(decode(&encode(&h,&[]).unwrap()).is_err());
    for bytes in [b"{\"v\":1,\"v\":1}".as_slice(),b"{ \"v\":1}".as_slice()] {assert!(canonical(bytes,SIGNER_HEADER_MAX_BYTES).is_err());}
    assert!(decode(&[0,0,4,1]).is_err());
}
#[test]
fn tokens_and_unsettled_work_are_bounded() {
    let mut budget=WorkBudget::new(0); assert!(budget.admit(0,0)); assert!(!budget.admit(1,0));
    assert!(!budget.admit(0,2_000_000_000)); budget.settled(); assert!(budget.admit(0,2_000_000_000));
}
#[test]
fn fixed_caller_buckets_and_rate_ceiling() {
    let mut budget=WorkBudget::new(0); assert!(!budget.admit(SIGNER_CONNECTIONS_MAX,0));
    for _ in 0..SIGNER_PER_CALLER_BURST_MAX {assert!(budget.admit(0,0));budget.settled();}
    assert!(!budget.admit(0,0)); assert!(budget.admit(1,0));
    let mut boundary=WorkBudget::new(0);
    for _ in 0..SIGNER_PER_CALLER_BURST_MAX {assert!(boundary.admit(0,999_000_000));boundary.settled();}
    assert!(!boundary.admit(0,1_000_000_000));
}
#[test]
fn deadline_and_grant_bind_request() {
    let frame=encode(&header(),&[]).unwrap();let (mut h,_)=decode(&frame).unwrap();
    let g=json!({"role":h.role,"epoch":1,"generation":1,"activation_id":h.activation_id,"lease_id":h.lease_id});
    assert!(header_matches(&h,&g,0));h.deadline_boottime_ns="1000000001".into();assert!(!header_matches(&h,&g,0));
    h.deadline_boottime_ns="1".into();assert!(!header_matches(&h,&g,1));h.generation=2;assert!(!header_matches(&h,&g,0));
}
#[test]
fn worker_response_never_forwards_extra_secret_fields() {
    let rows:serde_json::Value=serde_json::from_str(include_str!("../src/business_profile/role_vectors.json")).unwrap();
    use base64::{Engine,engine::general_purpose::URL_SAFE_NO_PAD};
    let row=&rows[0];let grant=json!({"kid":row["kid"],"public_key":URL_SAFE_NO_PAD.encode(hex::decode(row["public_key"].as_str().unwrap()).unwrap())});
    let mut response=json!({"op":"SIGNED","request_id":"r","kid":row["kid"],"signature":URL_SAFE_NO_PAD.encode(hex::decode(row["signature"].as_str().unwrap()).unwrap())});
    assert!(valid_signature_response(&response,"r",&grant));response["secret"]=json!("SENTINEL_KEY_MATERIAL");assert!(!valid_signature_response(&response,"r",&grant));
}
