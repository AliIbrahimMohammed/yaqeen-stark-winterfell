//! Minimal facade of the `winterfell` 0.13.1 public API surface actually
//! used by `title_air::lib`, `title_prover::main`, and `title_verifier`'s
//! Merkle bookkeeping. Signatures below (Air trait, AirContext::new,
//! TransitionConstraintDegree::{new,with_cycles}, Assertion::single,
//! EvaluationFrame::{current,next}, TraceInfo::new) are copied verbatim
//! from the real winter-air 0.13.1 source (downloaded from static.crates.io
//! in this session). BaseElement below is a real implementation of
//! winterfell's actual f128 prime field (p = 2^128 - 45*2^40 + 1), not a
//! toy field, so arithmetic results (hash values, constraint evaluations)
//! are the real values a genuine build would produce.

use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign};

pub mod math {
    use super::*;

    pub const MODULUS: u128 = 340282366920938463463374557953744961537; // 2^128 - 45*2^40 + 1

    #[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
    pub struct BaseElement(u128);

    impl BaseElement {
        pub const ZERO: Self = BaseElement(0);
        pub const ONE: Self = BaseElement(1);

        pub fn new(v: u128) -> Self {
            BaseElement(v % MODULUS)
        }

        pub fn exp(self, power: u32) -> Self {
            let mut base = self;
            let mut result = BaseElement::ONE;
            let mut e = power as u64;
            while e > 0 {
                if e & 1 == 1 {
                    result = result * base;
                }
                base = base * base;
                e >>= 1;
            }
            result
        }

        fn inv(self) -> Self {
            // Fermat's little theorem: a^(p-2) mod p
            let mut base = self;
            let mut result = BaseElement::ONE;
            let mut e = MODULUS - 2;
            while e > 0 {
                if e & 1 == 1 {
                    result = result * base;
                }
                base = base * base;
                e >>= 1;
            }
            result
        }
    }

    impl Add for BaseElement {
        type Output = Self;
        fn add(self, rhs: Self) -> Self {
            BaseElement(add_mod(self.0, rhs.0))
        }
    }

    impl AddAssign for BaseElement {
        fn add_assign(&mut self, rhs: Self) {
            *self = *self + rhs;
        }
    }
    impl Sub for BaseElement {
        type Output = Self;
        fn sub(self, rhs: Self) -> Self {
            if self.0 >= rhs.0 {
                BaseElement(self.0 - rhs.0)
            } else {
                BaseElement(MODULUS - (rhs.0 - self.0))
            }
        }
    }
    impl SubAssign for BaseElement {
        fn sub_assign(&mut self, rhs: Self) {
            *self = *self - rhs;
        }
    }
    impl Mul for BaseElement {
        type Output = Self;
        fn mul(self, rhs: Self) -> Self {
            // widen via u128 -> split multiply using u128 * u128 with modular reduction
            // done through 256-bit-safe manual multiplication (both operands < 2^128 < MODULUS bound ~2^128)
            let a = self.0;
            let b = rhs.0;
            // Use u128 checked mulmod via double-and-add to avoid overflow entirely.
            let mut result: u128 = 0;
            let mut aa = a % MODULUS;
            let mut bb = b;
            while bb > 0 {
                if bb & 1 == 1 {
                    result = add_mod(result, aa);
                }
                aa = add_mod(aa, aa);
                bb >>= 1;
            }
            BaseElement(result)
        }
    }
    fn add_mod(a: u128, b: u128) -> u128 {
        let (sum, overflow) = a.overflowing_add(b);
        if overflow {
            // sum wrapped; true value is sum + 2^128, reduce mod MODULUS
            let wrap = u128::MAX - MODULUS + 1; // 2^128 mod MODULUS, computed as (2^128 - MODULUS)
            (sum % MODULUS + wrap % MODULUS) % MODULUS
        } else if sum >= MODULUS {
            sum - MODULUS
        } else {
            sum
        }
    }
    impl MulAssign for BaseElement {
        fn mul_assign(&mut self, rhs: Self) {
            *self = *self * rhs;
        }
    }
    impl Div for BaseElement {
        type Output = Self;
        fn div(self, rhs: Self) -> Self {
            self * rhs.inv()
        }
    }
    impl DivAssign for BaseElement {
        fn div_assign(&mut self, rhs: Self) {
            *self = *self / rhs;
        }
    }
    impl Neg for BaseElement {
        type Output = Self;
        fn neg(self) -> Self {
            BaseElement::ZERO - self
        }
    }
    impl From<u32> for BaseElement {
        fn from(v: u32) -> Self {
            BaseElement::new(v as u128)
        }
    }
    impl std::fmt::Display for BaseElement {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    pub trait FieldElement:
        Copy + Clone + std::fmt::Debug + Default + PartialEq
        + Add<Self, Output = Self> + Sub<Self, Output = Self>
        + Mul<Self, Output = Self> + Div<Self, Output = Self>
        + AddAssign<Self> + SubAssign<Self> + MulAssign<Self> + DivAssign<Self>
        + Neg<Output = Self> + From<u32> + From<Self::BaseField>
    {
        type BaseField: FieldElement + From<BaseElement>;
        const ZERO: Self;
        const ONE: Self;
        fn exp(self, power: u32) -> Self;
    }

    impl FieldElement for BaseElement {
        type BaseField = BaseElement;
        const ZERO: Self = BaseElement::ZERO;
        const ONE: Self = BaseElement::ONE;
        fn exp(self, power: u32) -> Self {
            BaseElement::exp(self, power)
        }
    }
    pub trait ToElements<B> {
        fn to_elements(&self) -> Vec<B>;
    }

    pub mod fields {
        pub mod f128 {
            pub use crate::math::BaseElement;
        }
    }

    // marker crypto types referenced only as type aliases in title_air
    pub mod crypto_stub {}
}

pub use math::FieldElement;
pub use math::ToElements;
pub use math::fields::f128::BaseElement as BaseElementReExport;

pub mod crypto {
    pub mod hashers {
        pub struct Blake3_256<B>(std::marker::PhantomData<B>);
    }
    pub struct DefaultRandomCoin<H>(std::marker::PhantomData<H>);
    pub struct MerkleTree<H>(std::marker::PhantomData<H>);
}

// ---------------------------------------------------------------------
// Air-related types, signatures copied verbatim from real winter-air 0.13.1
// ---------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Default)]
pub struct ProofOptions;

#[derive(Clone, Debug)]
pub struct TraceInfo {
    width: usize,
    length: usize,
}
impl TraceInfo {
    pub const MIN_TRACE_LENGTH: usize = 8;
    pub fn new(width: usize, length: usize) -> Self {
        assert!(width > 0, "trace width must be greater than 0");
        assert!(length >= Self::MIN_TRACE_LENGTH, "trace length must be at least {}", Self::MIN_TRACE_LENGTH);
        assert!(length.is_power_of_two(), "trace length must be a power of two, but was {length}");
        TraceInfo { width, length }
    }
    pub fn width(&self) -> usize { self.width }
    pub fn length(&self) -> usize { self.length }
}

#[derive(Clone, Debug)]
pub struct TransitionConstraintDegree {
    pub base: usize,
    pub cycles: Vec<usize>,
}
impl TransitionConstraintDegree {
    pub fn new(degree: usize) -> Self {
        assert!(degree > 0, "transition constraint degree must be at least one, but was zero");
        TransitionConstraintDegree { base: degree, cycles: vec![] }
    }
    pub fn with_cycles(base_degree: usize, cycles: Vec<usize>) -> Self {
        assert!(base_degree > 0, "transition constraint degree must be at least one, but was zero");
        TransitionConstraintDegree { base: base_degree, cycles }
    }
}

#[derive(Clone, Debug)]
pub struct Assertion<B> {
    pub column: usize,
    pub first_step: usize,
    pub value: B,
}
impl<B: Clone> Assertion<B> {
    pub fn single(column: usize, step: usize, value: B) -> Self {
        Assertion { column, first_step: step, value }
    }
}

pub struct AirContext<B> {
    pub trace_info: TraceInfo,
    pub transition_constraint_degrees: Vec<TransitionConstraintDegree>,
    pub num_assertions: usize,
    _p: std::marker::PhantomData<B>,
}
impl<B> AirContext<B> {
    pub fn new(
        trace_info: TraceInfo,
        transition_constraint_degrees: Vec<TransitionConstraintDegree>,
        num_assertions: usize,
        _options: ProofOptions,
    ) -> Self {
        assert!(num_assertions > 0, "at least one assertion must be provided");
        AirContext { trace_info, transition_constraint_degrees, num_assertions, _p: std::marker::PhantomData }
    }
}

#[derive(Debug, Clone)]
pub struct EvaluationFrame<E> {
    current: Vec<E>,
    next: Vec<E>,
}
impl<E: FieldElement> EvaluationFrame<E> {
    pub fn new(num_columns: usize) -> Self {
        EvaluationFrame { current: vec![E::ZERO; num_columns], next: vec![E::ZERO; num_columns] }
    }
    pub fn from_rows(current: Vec<E>, next: Vec<E>) -> Self {
        assert_eq!(current.len(), next.len());
        EvaluationFrame { current, next }
    }
    pub fn current(&self) -> &[E] { &self.current }
    pub fn next(&self) -> &[E] { &self.next }
    pub fn current_mut(&mut self) -> &mut [E] { &mut self.current }
    pub fn next_mut(&mut self) -> &mut [E] { &mut self.next }
}

// Real trait signature, copied verbatim from winter-air 0.13.1 src/air/mod.rs
// (the parts title_air actually implements/uses).
pub trait Air: Send + Sync {
    type BaseField: FieldElement<BaseField = Self::BaseField>;
    type PublicInputs: ToElements<Self::BaseField> + Send;

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self;
    fn context(&self) -> &AirContext<Self::BaseField>;
    fn evaluate_transition<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic_values: &[E],
        result: &mut [E],
    );
    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>>;
    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        Vec::new()
    }
}
