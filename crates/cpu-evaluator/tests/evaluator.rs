use kryvola_cpu_evaluator::{EvaluationBinding, EvaluationError, evaluate};
use kryvola_owner_crypto::{OpenBinding, OwnerKey, blob_digest};

#[test]
fn fixed_circuit_accepts_only_bound_conformant_pairs() {
    let owner = OwnerKey::generate().unwrap();
    let key = owner.evaluation_key();
    let input = owner.encrypt_pair([255, 17]).unwrap();
    let binding = EvaluationBinding {
        evaluation_key_digest: blob_digest(key),
        input_blob_digest: blob_digest(&input),
    };
    let result = evaluate(binding, key, &input).unwrap();
    assert_eq!(
        owner
            .open_result(
                OpenBinding {
                    evaluation_key_digest: binding.evaluation_key_digest,
                    result_blob_digest: blob_digest(&result),
                },
                &result
            )
            .unwrap(),
        [89, 250]
    );
    assert_eq!(
        evaluate(
            EvaluationBinding {
                evaluation_key_digest: [0; 32],
                ..binding
            },
            key,
            &input
        ),
        Err(EvaluationError::Binding)
    );
    assert_eq!(
        evaluate(
            EvaluationBinding {
                input_blob_digest: [0; 32],
                ..binding
            },
            key,
            &input
        ),
        Err(EvaluationError::Binding)
    );
    for input in [
        vec![],
        input[..input.len() - 1].to_vec(),
        [&input[..], &[0]].concat(),
    ] {
        assert_eq!(
            evaluate(
                EvaluationBinding {
                    input_blob_digest: blob_digest(&input),
                    ..binding
                },
                key,
                &input
            ),
            Err(EvaluationError::Framing)
        );
    }
    let mut malformed = input.clone();
    malformed[16] ^= 1;
    assert_eq!(
        evaluate(
            EvaluationBinding {
                input_blob_digest: blob_digest(&malformed),
                ..binding
            },
            key,
            &malformed
        ),
        Err(EvaluationError::Native)
    );
    let mut trailing_key = key.to_vec();
    trailing_key.push(0);
    assert_eq!(
        evaluate(
            EvaluationBinding {
                evaluation_key_digest: blob_digest(&trailing_key),
                ..binding
            },
            &trailing_key,
            &input
        ),
        Err(EvaluationError::Framing)
    );
    assert_eq!(
        evaluate(binding, key, &vec![0; 2 * ((1 << 20) + 8) + 1]),
        Err(EvaluationError::Size)
    );
    assert_eq!(
        evaluate(binding, &vec![0; (64 << 20) + 1], &input),
        Err(EvaluationError::Size)
    );
}

#[test]
fn foreign_parameter_evaluation_material_is_rejected() {
    use tfhe::{
        ClientKey, CompressedServerKey, ConfigBuilder, safe_serialization::safe_serialize,
        shortint::parameters::v1_4::V1_4_PARAM_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128 as OTHER,
    };
    let owner = OwnerKey::generate().unwrap();
    let input = owner.encrypt_pair([0, 255]).unwrap();
    // Alternate parameters are a negative control, never an enabled profile.
    let client = ClientKey::generate(ConfigBuilder::with_custom_parameters(OTHER).build());
    let mut key = Vec::new();
    safe_serialize(&CompressedServerKey::new(&client), &mut key, 64 << 20).unwrap();
    assert_eq!(
        evaluate(
            EvaluationBinding {
                evaluation_key_digest: blob_digest(&key),
                input_blob_digest: blob_digest(&input),
            },
            &key,
            &input
        ),
        Err(EvaluationError::Native)
    );
}
