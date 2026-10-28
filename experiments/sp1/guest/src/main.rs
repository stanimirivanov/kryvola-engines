#![no_main]
sp1_zkvm::entrypoint!(main);

pub fn main() {
    let fields = [
        sp1_zkvm::io::read::<[u8; 32]>(),
        sp1_zkvm::io::read(),
        sp1_zkvm::io::read(),
    ];
    let mode = sp1_zkvm::io::read::<u8>();
    let journal = kryvola_sp1_statement::journal(fields, mode).expect("UNSUPPORTED_MODE");
    sp1_zkvm::io::commit_slice(&journal);
}
