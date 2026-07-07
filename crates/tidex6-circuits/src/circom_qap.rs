//! `CircomReduction` — witness-map QAP-редукция, совместимая со snarkjs, под
//! arkworks 0.5 (Путь A, церемония).
//!
//! Дефолтный arkworks (`LibsnarkReduction`) считает коэффициенты H-полинома
//! через `(AB - C)/Z` в coset-домене. snarkjs вместо этого берёт нечётные
//! коэффициенты `(AB - C)` в домене вдвое большего размера. Из-за этого
//! `h_query` точки в snarkjs-zkey не совпадают с тем, что ждёт дефолтный
//! arkworks-прувер, и proof не верифицируется. Эта редукция повторяет логику
//! snarkjs (портирована из проверенного `ark-circom`), чтобы наш arkworks-прувер
//! мог использовать церемониальный pk напрямую.
//!
//! Важно: для ПРУВА с готовым pk вызывается только `witness_map_from_matrices`.
//! `instance_map_with_evaluation` и `h_query_scalars` нужны лишь для setup —
//! делегируем их в `LibsnarkReduction` ради полноты трейта.

use ark_ff::PrimeField;
use ark_groth16::r1cs_to_qap::{evaluate_constraint, LibsnarkReduction, R1CSToQAP};
use ark_poly::EvaluationDomain;
use ark_relations::r1cs::{
    ConstraintMatrices, ConstraintSystemRef, Result as R1CSResult, SynthesisError,
};

/// snarkjs-совместимая QAP-редукция.
pub struct CircomReduction;

impl R1CSToQAP for CircomReduction {
    fn instance_map_with_evaluation<F: PrimeField, D: EvaluationDomain<F>>(
        cs: ConstraintSystemRef<F>,
        t: &F,
    ) -> Result<(Vec<F>, Vec<F>, Vec<F>, F, usize, usize), SynthesisError> {
        LibsnarkReduction::instance_map_with_evaluation::<F, D>(cs, t)
    }

    fn witness_map_from_matrices<F: PrimeField, D: EvaluationDomain<F>>(
        matrices: &ConstraintMatrices<F>,
        num_inputs: usize,
        num_constraints: usize,
        full_assignment: &[F],
    ) -> R1CSResult<Vec<F>> {
        let zero = F::zero();
        let domain = D::new(num_constraints + num_inputs)
            .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        let domain_size = domain.size();

        let mut a = vec![zero; domain_size];
        let mut b = vec![zero; domain_size];

        for (i, (at_i, bt_i)) in matrices.a.iter().zip(matrices.b.iter()).enumerate() {
            a[i] = evaluate_constraint::<F, F, F>(at_i, full_assignment);
            b[i] = evaluate_constraint::<F, F, F>(bt_i, full_assignment);
        }
        {
            let start = num_constraints;
            let end = start + num_inputs;
            a[start..end].clone_from_slice(&full_assignment[..num_inputs]);
        }

        // Для удовлетворяющего witness A·s·B·s == C·s в точках ограничений,
        // поэтому C можно взять как поэлементное произведение a·b (экономит
        // проход по матрице C) — ровно как делает snarkjs/ark-circom.
        let mut c = vec![zero; domain_size];
        for i in 0..num_constraints {
            c[i] = a[i] * b[i];
        }

        domain.ifft_in_place(&mut a);
        domain.ifft_in_place(&mut b);

        // Сдвиг на корень 2n-го порядка (домен вдвое больше) — «нечётный» coset.
        let root_of_unity = {
            let domain_size_double = 2 * domain_size;
            let domain_double = D::new(domain_size_double)
                .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
            domain_double.element(1)
        };
        D::distribute_powers_and_mul_by_const(&mut a, root_of_unity, F::one());
        D::distribute_powers_and_mul_by_const(&mut b, root_of_unity, F::one());

        domain.fft_in_place(&mut a);
        domain.fft_in_place(&mut b);

        let mut ab = domain.mul_polynomials_in_evaluation_domain(&a, &b);
        drop(a);
        drop(b);

        domain.ifft_in_place(&mut c);
        D::distribute_powers_and_mul_by_const(&mut c, root_of_unity, F::one());
        domain.fft_in_place(&mut c);

        for (ab_i, c_i) in ab.iter_mut().zip(c.iter()) {
            *ab_i -= c_i;
        }

        Ok(ab)
    }

    fn h_query_scalars<F: PrimeField, D: EvaluationDomain<F>>(
        max_power: usize,
        t: F,
        zt: F,
        delta_inverse: F,
    ) -> Result<Vec<F>, SynthesisError> {
        LibsnarkReduction::h_query_scalars::<F, D>(max_power, t, zt, delta_inverse)
    }
}
