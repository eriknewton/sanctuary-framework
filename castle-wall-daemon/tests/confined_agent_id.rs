use serde::Deserialize;

mod isolation;

#[derive(Deserialize)]
struct ConfinedAgentIdVectors {
    valid: Vec<String>,
    invalid: Vec<String>,
}

#[derive(Deserialize)]
struct ConfinedAgentIdRefusalVectors {
    cases: Vec<ConfinedAgentIdRefusalCase>,
}

#[derive(Deserialize)]
struct ConfinedAgentIdRefusalCase {
    name: String,
    kind: String,
    rule_id: String,
    agent_id: String,
    admitted_uid: u32,
    expected: ConfinedAgentIdRefusalExpected,
}

#[derive(Deserialize)]
struct ConfinedAgentIdRefusalExpected {
    shared: Option<String>,
    rust: Option<String>,
}

#[test]
fn confined_agent_id_form_matches_the_shared_vector_set() {
    let _suite = isolation::guard();
    let vectors: ConfinedAgentIdVectors =
        serde_json::from_str(include_str!("../test-vectors/confined-agent-id-v1.json")).unwrap();
    let accepted: Vec<_> = vectors
        .valid
        .iter()
        .map(|id| {
            (
                id.as_str(),
                castle_wall_daemon::nftables::parse_confined_agent_id(id).is_some(),
            )
        })
        .collect();
    assert_eq!(
        accepted,
        vectors
            .valid
            .iter()
            .map(|id| (id.as_str(), true))
            .collect::<Vec<_>>()
    );
    let refused: Vec<_> = vectors
        .invalid
        .iter()
        .map(|id| {
            (
                id.as_str(),
                castle_wall_daemon::nftables::parse_confined_agent_id(id).is_some(),
            )
        })
        .collect();
    assert_eq!(
        refused,
        vectors
            .invalid
            .iter()
            .map(|id| (id.as_str(), false))
            .collect::<Vec<_>>()
    );
}

#[test]
fn confined_agent_id_refusals_match_the_shared_message_vector_set() {
    let _suite = isolation::guard();
    let vectors: ConfinedAgentIdRefusalVectors = serde_json::from_str(include_str!(
        "../test-vectors/confined-agent-id-refusals-v1.json"
    ))
    .unwrap();

    for case in vectors.cases {
        let error = match case.kind.as_str() {
            "malformed" => {
                castle_wall_daemon::policy::ConfinedAgentScopeError::MalformedAgentScope {
                    rule_id: case.rule_id,
                    agent_id: case.agent_id,
                    expected_form: castle_wall_daemon::nftables::CONFINED_AGENT_ID_FORM,
                }
            }
            "wrong_uid" => {
                castle_wall_daemon::policy::ConfinedAgentScopeError::AgentScopeOutsideAdmission {
                    rule_id: case.rule_id,
                    agent_id: case.agent_id,
                    admitted_uid: case.admitted_uid,
                }
            }
            other => panic!("unknown confined-agent-id refusal kind {other}"),
        };
        let expected = case.expected.rust.or(case.expected.shared).unwrap();
        assert_eq!(error.to_string(), expected, "{}", case.name);
    }
}
