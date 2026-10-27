#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args().skip(1).collect::<Vec<_>>() != ["conformance"] {
        return Err("usage: kryvola-fake-engine conformance (test-only)".into());
    }
    kryvola_fake_engine::conformance::run().await?;
    println!("FAKE ENGINE loopback conformance passed; no inference or production capability");
    Ok(())
}
