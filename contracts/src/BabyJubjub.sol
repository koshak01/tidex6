// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {BabyJubjubConstants as C} from "./BabyJubjubConstants.sol";

/// @title Baby Jubjub point arithmetic for confidential balances
/// @notice The confidential token stores balances as twisted ElGamal
///         ciphertexts, and every operation on a balance is a point addition:
///         crediting adds, spending subtracts. This library is that addition.
///
///         The curve is the one the circuits use (`BabyJubjubConstants`, form
///         `x^2 + y^2 = 1 + d*x^2*y^2`, so `a = 1`). Its coordinates are
///         elements of the BN254 scalar field, which is why a Groth16 circuit
///         over BN254 can do this arithmetic natively — and why the contract
///         can agree with the circuit on the result bit for bit.
///
/// @dev Why extended coordinates. Affine addition needs a modular inverse,
///      and an inverse costs a `MODEXP` call. Two inverses per ciphertext
///      addition would be tolerable; sixty-four of them inside a scalar
///      multiplication would not. In extended coordinates `(X, Y, T, Z)` with
///      `x = X/Z`, `y = Y/Z`, `T = X*Y/Z`, addition and doubling are pure
///      multiplications, and the single inverse happens once at the end.
///
/// @dev Points that arrive as Groth16 public inputs are already known to be on
///      the curve and in the prime-order subgroup: the circuits check that
///      (`token/gadget.rs`), and a public input the verifier accepted is a
///      point the circuit constrained. This library therefore does no
///      membership test of its own — it is arithmetic, not validation. The one
///      point built inside the contract is `m*G`, and it is on the curve
///      because `G` is.
library BabyJubjub {
    /// Affine point. The neutral element is `(0, 1)`.
    struct Point {
        uint256 x;
        uint256 y;
    }

    /// Extended coordinates, used only inside this library.
    struct Ext {
        uint256 x;
        uint256 y;
        uint256 t;
        uint256 z;
    }

    /// The neutral element, `(0, 1)`.
    ///
    /// A fresh account's balance is this point, and it is also the handle of a
    /// ciphertext that carries no blinding — which is exactly what `wrap`
    /// produces, since the amount it commits to is public anyway.
    ///
    /// # Возвращает
    /// * `Point` — the identity
    function identity() internal pure returns (Point memory) {
        return Point(0, 1);
    }

    /// Is this the neutral element?
    ///
    /// # Параметры
    /// * `p` — point to test
    ///
    /// # Возвращает
    /// * `bool` — true for `(0, 1)`
    function isIdentity(Point memory p) internal pure returns (bool) {
        return p.x == 0 && p.y == 1;
    }

    /// The additive inverse: `-(x, y) = (-x, y)`.
    ///
    /// # Параметры
    /// * `p` — point to negate
    ///
    /// # Возвращает
    /// * `Point` — the negated point
    function neg(Point memory p) internal pure returns (Point memory) {
        return Point(p.x == 0 ? 0 : C.P - p.x, p.y);
    }

    /// Point addition.
    ///
    /// Converts both operands to extended coordinates, adds there, and
    /// normalizes once — one inverse per call.
    ///
    /// # Параметры
    /// * `p1` — first summand
    /// * `p2` — second summand
    ///
    /// # Возвращает
    /// * `Point` — `p1 + p2` in affine coordinates
    function add(Point memory p1, Point memory p2) internal view returns (Point memory) {
        return normalize(addExt(toExt(p1), toExt(p2)));
    }

    /// Point subtraction, `p1 - p2`.
    ///
    /// Spending from a confidential balance is this operation: the contract
    /// subtracts the ciphertext of the amount from the ciphertext of the
    /// balance without learning either number.
    ///
    /// # Параметры
    /// * `p1` — minuend
    /// * `p2` — subtrahend
    ///
    /// # Возвращает
    /// * `Point` — `p1 - p2` in affine coordinates
    function sub(Point memory p1, Point memory p2) internal view returns (Point memory) {
        return normalize(addExt(toExt(p1), toExt(neg(p2))));
    }

    /// `m * G` for an amount-sized scalar.
    ///
    /// Needed where an amount is public and the contract has to build its
    /// ciphertext itself: `wrap` credits `m*G`, `unwrap` debits it. The scalar
    /// is a `uint64`, so this is sixty-four doublings and at most sixty-four
    /// additions, all in extended coordinates with a single inverse at the
    /// end — a few thousand multiplications, not sixty-four inversions.
    ///
    /// @dev The scalar is deliberately `uint64`: it is an amount, and the
    ///      circuits' range proofs cover exactly 64 bits. Widening this to a
    ///      general scalar would also make it a general-purpose multiplier for
    ///      secret keys, which has no place in a contract.
    ///
    /// # Параметры
    /// * `m` — the amount
    ///
    /// # Возвращает
    /// * `Point` — `m*G`, and the identity when `m` is zero
    function mulG(uint64 m) internal view returns (Point memory) {
        Ext memory acc = toExt(identity());
        Ext memory base = toExt(Point(C.GX, C.GY));
        uint64 rest = m;
        while (rest != 0) {
            if (rest & 1 == 1) {
                acc = addExt(acc, base);
            }
            base = addExt(base, base);
            rest >>= 1;
        }
        return normalize(acc);
    }

    /// Affine to extended: `T = x*y`, `Z = 1`.
    function toExt(Point memory p) private pure returns (Ext memory) {
        return Ext(p.x, p.y, mulmod(p.x, p.y, C.P), 1);
    }

    /// Extended addition for `a = 1` (the "add-2008-hwcd" formulas).
    ///
    /// Unified: the same expression adds two distinct points and doubles one,
    /// so there is no special case to branch on and no way to take the wrong
    /// branch on attacker-chosen input.
    function addExt(Ext memory q1, Ext memory q2) private pure returns (Ext memory r) {
        r = Ext(0, 0, 0, 0);
        uint256 p = C.P;
        uint256 d = C.D;
        // Written in assembly with deliberately few live variables. The same
        // arithmetic in Solidity needs nine locals plus a nested expression,
        // which is past what the legacy code generator can address on the
        // stack — and switching the build to via-IR would change the bytecode
        // of every contract already verified under the current profile.
        //
        // Intermediate E and H are parked in `r` itself (fresh memory, never
        // aliasing `q1` or `q2`), and the variables that held A and B are
        // reused for C and D once A and B are no longer needed.
        assembly ("memory-safe") {
            let a := mulmod(mload(q1), mload(q2), p)
            let b := mulmod(mload(add(q1, 0x20)), mload(add(q2, 0x20)), p)
            // E = (X1 + Y1)(X2 + Y2) - A - B, parked in r.x
            mstore(
                r,
                addmod(
                    addmod(
                        mulmod(
                            addmod(mload(q1), mload(add(q1, 0x20)), p),
                            addmod(mload(q2), mload(add(q2, 0x20)), p),
                            p
                        ),
                        sub(p, a),
                        p
                    ),
                    sub(p, b),
                    p
                )
            )
            // H = B - A (a = 1), parked in r.z
            mstore(add(r, 0x60), addmod(b, sub(p, a), p))
            // C = d * T1 * T2, reusing `a`
            a := mulmod(d, mulmod(mload(add(q1, 0x40)), mload(add(q2, 0x40)), p), p)
            // D = Z1 * Z2, reusing `b`
            b := mulmod(mload(add(q1, 0x60)), mload(add(q2, 0x60)), p)
            let f := addmod(b, sub(p, a), p)
            let g := addmod(b, a, p)
            let e := mload(r)
            let h := mload(add(r, 0x60))
            mstore(r, mulmod(e, f, p))
            mstore(add(r, 0x20), mulmod(g, h, p))
            mstore(add(r, 0x40), mulmod(e, h, p))
            mstore(add(r, 0x60), mulmod(f, g, p))
        }
    }

    /// Extended to affine: one inverse of `Z`.
    function normalize(Ext memory q) private view returns (Point memory) {
        uint256 zInv = inv(q.z);
        return Point(mulmod(q.x, zInv, C.P), mulmod(q.y, zInv, C.P));
    }

    /// Modular inverse via the `MODEXP` precompile: `z^(p-2) mod p`.
    ///
    /// @dev Fermat rather than extended Euclid because the precompile does the
    ///      whole exponentiation for a flat fee, while a Solidity Euclid loop
    ///      costs more and is longer to read. `z` is never zero here: `Z` is a
    ///      product of previous `Z`s and of `F*G`, and both vanish only for a
    ///      point off the curve, which the circuits rule out.
    function inv(uint256 z) private view returns (uint256 result) {
        uint256 p = C.P;
        bool ok;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, 0x20) // length of base
            mstore(add(ptr, 0x20), 0x20) // length of exponent
            mstore(add(ptr, 0x40), 0x20) // length of modulus
            mstore(add(ptr, 0x60), z)
            mstore(add(ptr, 0x80), sub(p, 2))
            mstore(add(ptr, 0xa0), p)
            ok := staticcall(gas(), 0x05, ptr, 0xc0, ptr, 0x20)
            result := mload(ptr)
        }
        require(ok, "modexp failed");
    }
}
