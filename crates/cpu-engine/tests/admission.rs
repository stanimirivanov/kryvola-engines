use kryvola_cpu_engine::{PARAMETERS, PROGRAM, admit};
use kryvola_engine_api::{codec, wire::ExecuteRequest};

#[test]
fn only_exact_trusted_execution_and_fixed_program_are_admitted() {
    let mut approved: ExecuteRequest = codec::fixture("ExecuteRequest");
    approved.program_digest = Some(PROGRAM.into());
    approved.parameter_set_digest = Some(PARAMETERS.into());
    approved.required_operators.push("MUL".into());
    let mut second = approved.input_refs[0].clone();
    second.manifest_digest = "b".repeat(64);
    approved.input_refs.push(second);
    assert!(admit(&approved, &approved).is_ok());
    let mut substituted = approved.clone();
    substituted.input_refs[0].manifest_digest = "f".repeat(64);
    assert!(admit(&approved, &substituted).is_err());
    substituted.program_digest = Some("a".repeat(64));
    assert!(admit(&substituted, &substituted).is_err());
}
