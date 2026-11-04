use kryvola_owner_crypto::{OpenBinding, OwnerError, OwnerKey, blob_digest};

#[test]
fn owner_opens_only_bound_fixed_shape_results() {
    let owner = OwnerKey::generate().unwrap();
    let pair = owner.encrypt_pair([255, 17]).unwrap();
    let binding = OpenBinding {
        evaluation_key_digest: blob_digest(owner.evaluation_key()),
        result_blob_digest: blob_digest(&pair),
    };
    assert_eq!(owner.open_result(binding, &pair).unwrap(), [255, 17]);
    assert_eq!(
        owner.open_result(
            OpenBinding {
                evaluation_key_digest: [0; 32],
                ..binding
            },
            &pair
        ),
        Err(OwnerError::Binding)
    );
    assert_eq!(
        owner.open_result(binding, &pair[..pair.len() - 1]),
        Err(OwnerError::Binding)
    );
    let mut malformed = pair.clone();
    malformed[16] ^= 1; // Change a native header version character.
    assert_eq!(
        owner.open_result(
            OpenBinding {
                result_blob_digest: blob_digest(&malformed),
                ..binding
            },
            &malformed,
        ),
        Err(OwnerError::Native),
    );
    assert_eq!(
        owner.open_result(binding, &vec![0; 2 * ((1 << 20) + 8) + 1]),
        Err(OwnerError::Size),
    );
    let mut trailing = pair.clone();
    trailing.push(0);
    assert!(
        owner
            .open_result(
                OpenBinding {
                    result_blob_digest: blob_digest(&trailing),
                    ..binding
                },
                &trailing
            )
            .is_err()
    );
}

#[test]
fn frozen_modular_circuit_round_trips_using_evaluation_material() {
    use std::io::Cursor;
    use tfhe::{
        CompressedServerKey, ConfigBuilder, FheUint8, FheUint8ConformanceParams,
        safe_serialization::{safe_deserialize_conformant, safe_serialize},
        shortint::parameters::v1_4::V1_4_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128 as PARAMETERS,
    };

    fn pairs(csv: &str) -> impl Iterator<Item = [u8; 2]> {
        csv.lines().skip(1).map(|line| {
            let (a, b) = line.split_once(',').unwrap();
            [a.parse().unwrap(), b.parse().unwrap()]
        })
    }

    fn evaluate(key: &[u8], input: &[u8]) -> Vec<u8> {
        let config = ConfigBuilder::with_custom_parameters(PARAMETERS).build();
        let key: CompressedServerKey =
            safe_deserialize_conformant(key, 64 << 20, &config.into()).unwrap();
        tfhe::set_server_key(key.decompress());
        let mut input = input;
        let mut next = || -> FheUint8 {
            let (length, tail) = input.split_first_chunk::<8>().unwrap();
            let (bytes, rest) = tail.split_at(u64::from_le_bytes(*length) as usize);
            input = rest;
            safe_deserialize_conformant(
                Cursor::new(bytes),
                1 << 20,
                &FheUint8ConformanceParams::from(PARAMETERS),
            )
            .unwrap()
        };
        let a = next();
        let b = next();
        assert!(input.is_empty());
        let output = [&a * 3u8 + &b * 5u8 + 7u8, &a * &b + 11u8];
        let mut result = Vec::new();
        for ciphertext in output {
            let mut bytes = Vec::new();
            safe_serialize(&ciphertext, &mut bytes, 1 << 20).unwrap();
            result.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
            result.extend_from_slice(&bytes);
        }
        tfhe::unset_server_key();
        result
    }

    let owner = OwnerKey::generate().unwrap();
    let inputs = pairs(include_str!(
        "../../../experiments/tfhe/fixtures/fhe-q1/inputs.csv"
    ));
    let expected = pairs(include_str!(
        "../../../experiments/tfhe/fixtures/fhe-q1/expected.csv"
    ));
    for (index, (input, expected)) in inputs.zip(expected).enumerate() {
        if ![0, 9, 90, 99].contains(&index) {
            continue;
        }
        let input = owner.encrypt_pair(input).unwrap();
        let result = evaluate(owner.evaluation_key(), &input);
        let binding = OpenBinding {
            evaluation_key_digest: blob_digest(owner.evaluation_key()),
            result_blob_digest: blob_digest(&result),
        };
        assert_eq!(
            owner.open_result(binding, &result).unwrap(),
            expected,
            "case {index}"
        );
    }
}
