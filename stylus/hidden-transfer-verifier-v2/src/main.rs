#![cfg_attr(not(any(test, feature = "export-abi")), no_main)]

#[cfg(feature = "export-abi")]
fn main() {
    tidex6_stylus_hidden_transfer_verifier_v2::print_from_args();
}

#[cfg(not(feature = "export-abi"))]
fn main() {}
