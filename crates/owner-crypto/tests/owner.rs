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
    let open_framed = |bytes: &[u8]| {
        owner.open_result(
            OpenBinding {
                result_blob_digest: spec_digest(bytes),
                ..binding
            },
            bytes,
        )
    };
    assert_eq!(open_framed(&trailing), Err(OwnerError::Framing));
    assert_eq!(
        open_framed(&pair[..pair.len() - 1]),
        Err(OwnerError::Framing)
    );
    for length in [0, CT_MAX + 1, u64::MAX] {
        let mut invalid = pair.clone();
        invalid[..8].copy_from_slice(&length.to_le_bytes());
        assert_eq!(open_framed(&invalid), Err(OwnerError::Size));
    }
}

const CASES: usize = 100;
const CT_MAX: u64 = 1 << 20;
const KEY_MAX: u64 = 64 << 20;

use std::io::Cursor;
use tfhe::{
    ClientKey, CompressedServerKey, ConfigBuilder, FheUint8, FheUint8ConformanceParams,
    prelude::FheTryEncrypt,
    safe_serialization::{safe_deserialize, safe_deserialize_conformant, safe_serialize},
    shortint::parameters::v1_4::{
        V1_4_PARAM_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128 as ALTERNATE,
        V1_4_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128 as PARAMETERS,
    },
};

fn spec_digest(bytes: &[u8]) -> [u8; 32] {
    let mut framed = b"kryvola/blob/v1\0".to_vec();
    framed.extend_from_slice(bytes);
    *blake3::hash(&framed).as_bytes()
}

fn pack(ciphertexts: [FheUint8; 2]) -> Vec<u8> {
    let mut result = Vec::new();
    for ciphertext in ciphertexts {
        let mut encoded = Vec::new();
        safe_serialize(&ciphertext, &mut encoded, CT_MAX).unwrap();
        result.extend_from_slice(&(encoded.len() as u64).to_le_bytes());
        result.extend_from_slice(&encoded);
    }
    result
}

fn frame<'a>(pair: &mut &'a [u8]) -> &'a [u8] {
    let (length, tail) = pair.split_first_chunk::<8>().unwrap();
    let length = u64::from_le_bytes(*length);
    assert!((1..=CT_MAX).contains(&length));
    let (bytes, rest) = tail.split_at(length as usize);
    *pair = rest;
    bytes
}

fn evaluator_key(bytes: &[u8]) -> tfhe::ServerKey {
    // The only key bytes given to the evaluator must decode as evaluation
    // material, with no trailing bytes or client-key envelope.
    assert!(safe_deserialize::<ClientKey>(bytes, KEY_MAX).is_err());
    let mut cursor = Cursor::new(bytes);
    let config = ConfigBuilder::with_custom_parameters(PARAMETERS).build();
    let key: CompressedServerKey =
        safe_deserialize_conformant(&mut cursor, KEY_MAX, &config.into()).unwrap();
    assert_eq!(cursor.position(), bytes.len() as u64);
    key.decompress()
}

fn evaluate(mut input: &[u8]) -> Vec<u8> {
    let mut next = || -> FheUint8 {
        let bytes = frame(&mut input);
        assert!(safe_deserialize::<ClientKey>(bytes, CT_MAX).is_err());
        let mut cursor = Cursor::new(bytes);
        let ciphertext = safe_deserialize_conformant(
            &mut cursor,
            CT_MAX,
            &FheUint8ConformanceParams::from(PARAMETERS),
        )
        .unwrap();
        assert_eq!(cursor.position(), bytes.len() as u64);
        ciphertext
    };
    let a = next();
    let b = next();
    assert!(input.is_empty());
    pack([&a * 3u8 + &b * 5u8 + 7u8, &a * &b + 11u8])
}

#[test]
fn frozen_modular_circuit_round_trips_using_evaluation_material() {
    fn pairs(csv: &str, header: &str) -> Vec<[u8; 2]> {
        let mut lines = csv.lines();
        assert_eq!(lines.next(), Some(header));
        let rows: Vec<_> = lines
            .map(|line| {
                let (a, b) = line.split_once(',').unwrap();
                [a.parse().unwrap(), b.parse().unwrap()]
            })
            .collect();
        assert_eq!(rows.len(), CASES);
        rows
    }

    let inputs = pairs(
        include_str!("../../../experiments/tfhe/fixtures/fhe-q1/inputs.csv"),
        "x0,x1",
    );
    let expected = pairs(
        include_str!("../../../experiments/tfhe/fixtures/fhe-q1/expected.csv"),
        "y0,y1",
    );
    let boundaries = [
        ([0, 255], [2, 11]),
        ([255, 0], [4, 11]),
        ([255, 255], [255, 12]),
        ([128, 127], [2, 139]),
    ];

    let owner = OwnerKey::generate().unwrap();
    let evaluation = owner.evaluation_key();
    let evaluation_key_digest = spec_digest(evaluation);
    let mut executed = 0;
    tfhe::with_server_key_as_context(evaluator_key(evaluation), || {
        for (index, (input, expected)) in inputs
            .into_iter()
            .zip(expected)
            .chain(boundaries)
            .enumerate()
        {
            let input = owner.encrypt_pair(input).unwrap();
            let result = evaluate(&input);
            let binding = OpenBinding {
                evaluation_key_digest,
                result_blob_digest: spec_digest(&result),
            };
            assert_eq!(
                owner.open_result(binding, &result).unwrap(),
                expected,
                "case {index}"
            );
            executed += 1;
        }
    });
    assert_eq!(
        executed,
        CASES + boundaries.len(),
        "every frozen and boundary case must execute"
    );
}

#[test]
fn wrong_parameters_reach_native_conformance_with_valid_binding() {
    let owner = OwnerKey::generate().unwrap();
    let alternate = ClientKey::generate(ConfigBuilder::with_custom_parameters(ALTERNATE).build());
    let valid = owner.encrypt_pair([19, 23]).unwrap();
    let valid_binding = OpenBinding {
        evaluation_key_digest: spec_digest(owner.evaluation_key()),
        result_blob_digest: spec_digest(&valid),
    };
    assert_eq!(owner.open_result(valid_binding, &valid), Ok([19, 23]));

    let foreign = pack([
        FheUint8::try_encrypt(19u8, &alternate).unwrap(),
        FheUint8::try_encrypt(23u8, &alternate).unwrap(),
    ]);
    let mut remainder = foreign.as_slice();
    for _ in 0..2 {
        let encoded = frame(&mut remainder);
        let mut cursor = Cursor::new(encoded);
        let _: FheUint8 = safe_deserialize_conformant(
            &mut cursor,
            CT_MAX,
            &FheUint8ConformanceParams::from(ALTERNATE),
        )
        .unwrap();
        assert_eq!(cursor.position(), encoded.len() as u64);
        assert!(
            safe_deserialize_conformant::<FheUint8>(
                encoded,
                CT_MAX,
                &FheUint8ConformanceParams::from(PARAMETERS),
            )
            .is_err()
        );
    }
    assert!(remainder.is_empty());

    let foreign_binding = OpenBinding {
        result_blob_digest: spec_digest(&foreign),
        ..valid_binding
    };
    assert_eq!(
        owner.open_result(valid_binding, &foreign),
        Err(OwnerError::Binding)
    );
    assert_eq!(
        owner.open_result(foreign_binding, &foreign),
        Err(OwnerError::Native)
    );
}
