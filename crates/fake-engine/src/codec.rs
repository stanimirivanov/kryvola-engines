//! Adapt Tonic's Codec extension point; Prost parses bytes, spec schemas own structure.
use bytes::{Buf, BufMut};
use prost::Message;
use prost_reflect::{DescriptorPool, DynamicMessage, SerializeOptions, Value};
use serde_json::Value as Json;
use std::{collections::BTreeMap, marker::PhantomData, sync::OnceLock};
use tonic::{
    Status,
    codec::{Codec, DecodeBuf, Decoder, EncodeBuf, Encoder},
};

struct Context {
    pool: DescriptorPool,
    schemas: BTreeMap<String, jsonschema::Validator>,
}
fn context() -> &'static Context {
    static CONTEXT: OnceLock<Context> = OnceLock::new();
    CONTEXT.get_or_init(|| {
        let raw: BTreeMap<String, Json> =
            serde_json::from_slice(include_bytes!("../../../contracts/native/schemas.json"))
                .expect("pinned schemas");
        Context {
            pool: DescriptorPool::decode(
                include_bytes!("../../../contracts/native/descriptor.bin").as_slice(),
            )
            .expect("pinned descriptor"),
            schemas: raw
                .into_iter()
                .map(|(name, s)| (name, jsonschema::validator_for(&s).expect("pinned schema")))
                .collect(),
        }
    })
}
fn known(message: &DynamicMessage) -> bool {
    message.unknown_fields().next().is_none()
        && message.fields().all(|(_, v)| match v {
            Value::Message(m) => known(m),
            Value::List(a) => a.iter().all(|v| match v {
                Value::Message(m) => known(m),
                _ => true,
            }),
            _ => true,
        })
}
pub fn validate<T: Message>(bytes: &[u8]) -> Result<(), Status> {
    if bytes.len() > 65536 {
        return Err(Status::resource_exhausted("CONTROL_TOO_LARGE"));
    }
    let name = std::any::type_name::<T>()
        .rsplit("::")
        .next()
        .ok_or_else(|| Status::internal("TYPE"))?;
    let ctx = context();
    let descriptor = ctx
        .pool
        .get_message_by_name(&format!("kryvola.spec.v1.{name}"))
        .ok_or_else(|| Status::internal("TYPE"))?;
    let message = DynamicMessage::decode(descriptor, bytes)
        .map_err(|_| Status::invalid_argument("INVALID_DESCRIPTOR"))?;
    if !known(&message) {
        return Err(Status::invalid_argument("INVALID_DESCRIPTOR"));
    }
    let value = message
        .serialize_with_options(
            serde_json::value::Serializer,
            &SerializeOptions::new()
                .use_proto_field_name(true)
                .skip_default_fields(false),
        )
        .map_err(|_| Status::invalid_argument("INVALID_DESCRIPTOR"))?;
    if ctx.schemas.get(name).is_none_or(|s| !s.is_valid(&value)) {
        return Err(Status::invalid_argument("INVALID_DESCRIPTOR"));
    }
    Ok(())
}
pub fn fixture<T: Message + Default>(name: &str) -> T {
    let values: Json =
        serde_json::from_slice(include_bytes!("../../../contracts/native/fixtures.json"))
            .expect("pinned fixture");
    let descriptor = context()
        .pool
        .get_message_by_name(&format!("kryvola.spec.v1.{name}"))
        .expect("pinned type");
    T::decode(
        DynamicMessage::deserialize(descriptor, values[name].clone())
            .expect("pinned fixture")
            .encode_to_vec()
            .as_slice(),
    )
    .expect("pinned message")
}

// The crate alias routes unchanged generated bindings through this strict codec factory.
pub struct ProstCodec<T, U>(PhantomData<(T, U)>);
impl<T, U> Default for ProstCodec<T, U> {
    fn default() -> Self {
        Self(PhantomData)
    }
}
pub struct ProstEncoder<T>(PhantomData<T>);
pub struct ProstDecoder<T>(PhantomData<T>);
impl<T: Message + Send + 'static, U: Message + Default + Send + 'static> Codec
    for ProstCodec<T, U>
{
    type Encode = T;
    type Decode = U;
    type Encoder = ProstEncoder<T>;
    type Decoder = ProstDecoder<U>;
    fn encoder(&mut self) -> Self::Encoder {
        ProstEncoder(PhantomData)
    }
    fn decoder(&mut self) -> Self::Decoder {
        ProstDecoder(PhantomData)
    }
}
impl<T: Message> Encoder for ProstEncoder<T> {
    type Item = T;
    type Error = Status;
    fn encode(&mut self, item: T, dst: &mut EncodeBuf<'_>) -> Result<(), Status> {
        if item.encoded_len() > 65536 {
            return Err(Status::resource_exhausted("CONTROL_TOO_LARGE"));
        }
        let bytes = item.encode_to_vec();
        validate::<T>(&bytes)?;
        dst.put_slice(&bytes);
        Ok(())
    }
}
impl<T: Message + Default> Decoder for ProstDecoder<T> {
    type Item = T;
    type Error = Status;
    fn decode(&mut self, src: &mut DecodeBuf<'_>) -> Result<Option<T>, Status> {
        if src.remaining() > 65536 {
            return Err(Status::resource_exhausted("CONTROL_TOO_LARGE"));
        }
        let bytes = src.copy_to_bytes(src.remaining());
        validate::<T>(&bytes)?;
        T::decode(bytes)
            .map(Some)
            .map_err(|_| Status::invalid_argument("INVALID_DESCRIPTOR"))
    }
}
