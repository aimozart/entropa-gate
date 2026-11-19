//! 95 percent bounds of a failure rate (rule of three for zero events, Wilson otherwise; one-sided z = 1.645 as in the LS3d runner).
use crate::Refusal;

const Z: f64 = 1.645;

/// Lower and upper 95 percent bounds of a rate of `k` events in `n` cases.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Bounds {
    /// The lower bound (0 for zero events).
    pub lower: f64,
    /// The upper bound.
    pub upper: f64,
}

/// Bounds for `k` of `n`; `n == 0` or `k > n` is refused.
pub fn bounds(k: usize, n: usize) -> Result<Bounds, Refusal> {
    if n == 0 || k > n {
        return Err(Refusal::new(
            "the counts are impossible (n must be positive and k at most n)",
        ));
    }
    if k == 0 {
        return Ok(Bounds {
            lower: 0.0,
            upper: 1.0 - 0.05f64.powf(1.0 / n as f64),
        });
    }
    let (p, nf) = (k as f64 / n as f64, n as f64);
    let d = 1.0 + Z * Z / nf;
    let c = p + Z * Z / (2.0 * nf);
    let h = Z * (p * (1.0 - p) / nf + Z * Z / (4.0 * nf * nf)).sqrt();
    Ok(Bounds {
        lower: ((c - h) / d).max(0.0),
        upper: ((c + h) / d).min(1.0),
    })
}
