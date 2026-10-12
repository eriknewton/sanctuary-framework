use serde::Deserialize;

mod isolation;

#[derive(Deserialize)]
struct ConfinedAgentIdVectors {
    valid: Vec<String>,
    invalid: Vec<String>,
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
