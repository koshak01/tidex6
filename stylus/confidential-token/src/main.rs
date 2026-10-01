#![cfg_attr(not(any(test, feature = "export-abi")), no_main)]

#[cfg(feature = "export-abi")]
fn main() {
    tidex6_stylus_confidential_token::print_from_args();
}

#[cfg(not(feature = "export-abi"))]
fn main() {}
