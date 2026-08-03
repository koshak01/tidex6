// Unit tests for tidex6_private_transfer (local Leo test runner).
// Addresses from `leo account new` (valid bech32).
import tidex6_private_transfer.aleo;

program test_tidex6_private_transfer.aleo {
    // amount must be > 0
    @test
    @should_fail
    fn test_mint_zero_fails() {
        tidex6_private_transfer.aleo::mint_private(
            aleo1639nwum2mt0n0ukqwd4pay90u7uy2msmuvcc2htsc6djg94hdsrqzdjzdu,
            0u64
        );
    }

    // transfer_private of more than balance fails (u64 underflow)
    @test
    @should_fail
    fn test_overspend_fails() {
        let t = tidex6_private_transfer.aleo::mint_private(
            aleo1639nwum2mt0n0ukqwd4pay90u7uy2msmuvcc2htsc6djg94hdsrqzdjzdu,
            5u64
        );
        tidex6_private_transfer.aleo::transfer_private(
            t,
            aleo1275hjhv92r8yfzvce7jd2ymd265tlme568aj0ppqe7fqms6a9vqs2uk4tv,
            6u64
        );
    }

    // happy path: mint then full transfer
    @test
    fn test_transfer_full_ok() {
        let t = tidex6_private_transfer.aleo::mint_private(
            aleo1639nwum2mt0n0ukqwd4pay90u7uy2msmuvcc2htsc6djg94hdsrqzdjzdu,
            10u64
        );
        let out = tidex6_private_transfer.aleo::transfer_full(
            t,
            aleo1275hjhv92r8yfzvce7jd2ymd265tlme568aj0ppqe7fqms6a9vqs2uk4tv
        );
        assert_eq(out.amount, 10u64);
    }

    @noupgrade
    constructor() {}
}
