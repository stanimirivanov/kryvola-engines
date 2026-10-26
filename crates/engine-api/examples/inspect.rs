fn main() {
    println!(
        "component=kryvola-engines status=foundation execution_available=false control_max_bytes={}",
        kryvola_engine_api::limits::CONTROL_BYTES
    );
}
