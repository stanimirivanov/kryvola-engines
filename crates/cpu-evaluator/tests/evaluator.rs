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
    for length in [0u64, (1 << 20) + 1, u64::MAX] {
        let mut oversized_frame = input.clone();
        oversized_frame[..8].copy_from_slice(&length.to_le_bytes());
        assert_eq!(
            evaluate(
                EvaluationBinding {
                    input_blob_digest: blob_digest(&oversized_frame),
                    ..binding
                },
                key,
                &oversized_frame,
            ),
            Err(EvaluationError::Size),
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
        ClientKey, CompressedServerKey, ConfigBuilder, FheUint8, prelude::FheTryEncrypt,
        safe_serialization::safe_serialize,
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
    let mut foreign = Vec::new();
    for value in [0u8, 255] {
        let mut encoded = Vec::new();
        safe_serialize(
            &FheUint8::try_encrypt(value, &client).unwrap(),
            &mut encoded,
            1 << 20,
        )
        .unwrap();
        foreign.extend_from_slice(&(encoded.len() as u64).to_le_bytes());
        foreign.extend_from_slice(&encoded);
    }
    assert_eq!(
        evaluate(
            EvaluationBinding {
                evaluation_key_digest: blob_digest(owner.evaluation_key()),
                input_blob_digest: blob_digest(&foreign),
            },
            owner.evaluation_key(),
            &foreign,
        ),
        Err(EvaluationError::Native)
    );
}

#[test]
fn capability_matches_the_frozen_graph_and_rejects_other_programs() {
    use kryvola_cpu_evaluator::{CAPABILITY, evaluate_program};

    let graph = include_bytes!("../../../experiments/tfhe/fixtures/fhe-q1/program.txt");
    assert_eq!(
        CAPABILITY.program_digest,
        blake3::hash(graph).to_hex().as_str()
    );
    assert_eq!(CAPABILITY.assurance, "CONFIDENTIALITY_ONLY");
    assert_eq!(CAPABILITY.profile, "FHE-Q1");
    let binding = EvaluationBinding {
        evaluation_key_digest: [0; 32],
        input_blob_digest: [0; 32],
    };
    assert_eq!(
        evaluate_program(&"0".repeat(64), binding, b"", b""),
        Err(EvaluationError::Program)
    );
}

#[test]
fn frozen_corpus_boundaries_and_seeded_inputs_match_modular_reference() {
    use kryvola_cpu_evaluator::{CAPABILITY, evaluate_program};

    fn pairs(csv: &str, header: &str) -> Vec<[u8; 2]> {
        let mut lines = csv.lines();
        assert_eq!(lines.next(), Some(header));
        let pairs: Vec<_> = lines
            .map(|line| {
                let (left, right) = line.split_once(',').unwrap();
                [left.parse().unwrap(), right.parse().unwrap()]
            })
            .collect();
        assert_eq!(pairs.len(), 100);
        pairs
    }

    fn reference([a, b]: [u8; 2]) -> [u8; 2] {
        let (a, b) = (u32::from(a), u32::from(b));
        [
            ((3 * a + 5 * b + 7) % 256) as u8,
            ((a * b + 11) % 256) as u8,
        ]
    }

    let input = pairs(
        include_str!("../../../experiments/tfhe/fixtures/fhe-q1/inputs.csv"),
        "x0,x1",
    );
    let expected = pairs(
        include_str!("../../../experiments/tfhe/fixtures/fhe-q1/expected.csv"),
        "y0,y1",
    );
    for (input, expected) in input.iter().zip(&expected) {
        assert_eq!(reference(*input), *expected);
    }
    let mut seed = 0x5ab4_08c1_u32;
    let random = (0..16).map(|_| {
        seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        let [a, b, _, _] = seed.to_be_bytes();
        [a, b]
    });
    let inputs = input
        .into_iter()
        .chain([[0, 255], [255, 0], [255, 255], [128, 127]])
        .chain(random);

    let owner = OwnerKey::generate().unwrap();
    let key = owner.evaluation_key();
    let evaluation_key_digest = blob_digest(key);
    let mut tested = 0;
    for pair in inputs {
        let input = owner.encrypt_pair(pair).unwrap();
        let binding = EvaluationBinding {
            evaluation_key_digest,
            input_blob_digest: blob_digest(&input),
        };
        let result = evaluate_program(CAPABILITY.program_digest, binding, key, &input).unwrap();
        let opened = owner
            .open_result(
                OpenBinding {
                    evaluation_key_digest,
                    result_blob_digest: blob_digest(&result),
                },
                &result,
            )
            .unwrap();
        assert_eq!(opened, reference(pair), "case {tested}");
        tested += 1;
    }
    assert_eq!(tested, 120);
}
