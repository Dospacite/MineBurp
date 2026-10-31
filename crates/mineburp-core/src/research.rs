//! Bounded, transport-independent Intruder planning and sample analysis.
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackMode {
    Sniper,
    BatteringRam,
    Pitchfork,
    ClusterBomb,
}

/// Indices into each position's payload list. None leaves a position unchanged.
pub fn attack_plan(mode: AttackMode, lengths: &[usize]) -> Result<Vec<Vec<Option<usize>>>, String> {
    if lengths.is_empty() || lengths.len() > 16 || lengths.contains(&0) {
        return Err("Use 1–16 positions with nonempty payload lists".into());
    }
    let count = match mode {
        AttackMode::Sniper => lengths.iter().try_fold(0usize, |a, b| a.checked_add(*b)),
        AttackMode::BatteringRam => Some(lengths[0]),
        AttackMode::Pitchfork => lengths.iter().min().copied(),
        AttackMode::ClusterBomb => lengths.iter().try_fold(1usize, |a, b| a.checked_mul(*b)),
    }
    .filter(|n| *n <= 1000)
    .ok_or("An attack may contain at most 1,000 attempts")?;
    let mut plan = Vec::with_capacity(count);
    match mode {
        AttackMode::Sniper => {
            for (position, length) in lengths.iter().enumerate() {
                for i in 0..*length {
                    let mut row = vec![None; lengths.len()];
                    row[position] = Some(i);
                    plan.push(row);
                }
            }
        }
        AttackMode::BatteringRam | AttackMode::Pitchfork => {
            for i in 0..count {
                plan.push(vec![Some(i); lengths.len()]);
            }
        }
        AttackMode::ClusterBomb => {
            for mut i in 0..count {
                let mut row = vec![None; lengths.len()];
                for p in (0..lengths.len()).rev() {
                    row[p] = Some(i % lengths[p]);
                    i /= lengths[p];
                }
                plan.push(row);
            }
        }
    }
    Ok(plan)
}

#[derive(Debug, Serialize)]
pub struct PositionStats {
    pub offset: usize,
    pub samples: u32,
    pub distinct: usize,
    pub entropy_bits: f64,
    pub most_common_fraction: f64,
}
#[derive(Debug, Serialize)]
pub struct SequenceAnalysis {
    pub samples: usize,
    pub unique: usize,
    pub duplicates: usize,
    pub min_length: usize,
    pub max_length: usize,
    pub positions: Vec<PositionStats>,
    pub adjacent_equal: usize,
    pub serial_correlation: Option<f64>,
}

/// Statistics describe observed UTF-8 bytes, not cryptographic unpredictability.
pub fn analyze_sequence(samples: &[String]) -> Result<SequenceAnalysis, String> {
    if samples.len() < 2
        || samples.len() > 10_000
        || samples.iter().any(|s| s.is_empty() || s.len() > 4096)
        || samples.iter().map(String::len).sum::<usize>() > 4 * 1024 * 1024
    {
        return Err(
            "Use 2–10,000 nonempty samples, at most 4,096 bytes each and 4 MiB total".into(),
        );
    }
    let min_length = samples.iter().map(String::len).min().unwrap_or(0);
    let max_length = samples.iter().map(String::len).max().unwrap_or(0);
    let unique = samples.iter().collect::<HashSet<_>>().len();
    let positions = (0..max_length)
        .map(|offset| {
            let mut counts = [0u32; 256];
            for s in samples {
                if let Some(b) = s.as_bytes().get(offset) {
                    counts[*b as usize] += 1;
                }
            }
            let n: u32 = counts.iter().sum();
            let entropy_bits = counts
                .iter()
                .filter(|c| **c > 0)
                .map(|c| {
                    let p = f64::from(*c) / f64::from(n);
                    -p * p.log2()
                })
                .sum();
            PositionStats {
                offset,
                samples: n,
                distinct: counts.iter().filter(|c| **c > 0).count(),
                entropy_bits,
                most_common_fraction: f64::from(*counts.iter().max().unwrap_or(&0)) / f64::from(n),
            }
        })
        .collect();
    // Correlate bytes at matching offsets in consecutive samples, not artificial
    // boundaries produced by concatenating variable-length tokens.
    let (mut n, mut sx, mut sy, mut xx, mut yy, mut xy) = (0f64, 0f64, 0f64, 0f64, 0f64, 0f64);
    for pair in samples.windows(2) {
        for (&a, &b) in pair[0].as_bytes().iter().zip(pair[1].as_bytes()) {
            let (x, y) = (f64::from(a), f64::from(b));
            n += 1.;
            sx += x;
            sy += y;
            xx += x * x;
            yy += y * y;
            xy += x * y;
        }
    }
    let denominator = ((n * xx - sx * sx) * (n * yy - sy * sy)).sqrt();
    Ok(SequenceAnalysis {
        samples: samples.len(),
        unique,
        duplicates: samples.len() - unique,
        min_length,
        max_length,
        positions,
        adjacent_equal: samples.windows(2).filter(|p| p[0] == p[1]).count(),
        serial_correlation: (denominator > 0.)
            .then(|| ((n * xy - sx * sy) / denominator).clamp(-1., 1.)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn modes_and_bounds() {
        assert_eq!(
            attack_plan(AttackMode::Sniper, &[2, 3]).unwrap(),
            vec![
                vec![Some(0), None],
                vec![Some(1), None],
                vec![None, Some(0)],
                vec![None, Some(1)],
                vec![None, Some(2)]
            ]
        );
        assert_eq!(
            attack_plan(AttackMode::BatteringRam, &[2, 1]).unwrap(),
            vec![vec![Some(0), Some(0)], vec![Some(1), Some(1)]]
        );
        assert_eq!(
            attack_plan(AttackMode::Pitchfork, &[2, 3]).unwrap().len(),
            2
        );
        let product = attack_plan(AttackMode::ClusterBomb, &[2, 3]).unwrap();
        assert_eq!(product.len(), 6);
        assert_eq!(product[3], vec![Some(1), Some(0)]);
        assert!(attack_plan(AttackMode::ClusterBomb, &[usize::MAX, 2]).is_err());
        assert!(attack_plan(AttackMode::Sniper, &[]).is_err());
        assert!(attack_plan(AttackMode::Pitchfork, &[0]).is_err());
    }
    #[test]
    fn statistics_do_not_claim_randomness() {
        let constant = analyze_sequence(&["aaa".into(), "aaa".into()]).unwrap();
        assert_eq!(constant.duplicates, 1);
        assert!(constant.positions[0].entropy_bits.abs() < f64::EPSILON);
        assert_eq!(constant.serial_correlation, None);
        let varied = analyze_sequence(&["a".into(), "bb".into()]).unwrap();
        assert!((varied.positions[0].entropy_bits - 1.).abs() < f64::EPSILON);
        assert_eq!(varied.positions[1].samples, 1);
        assert!(analyze_sequence(&[String::new(), "a".into()]).is_err());
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PayloadGenerator {
    Numbers {
        start: String,
        end: String,
        step: String,
    },
    Boundaries {
        bits: u32,
        signed: bool,
    },
    Lengths {
        start: usize,
        end: usize,
        step: usize,
        unit: String,
    },
    Values {
        values: Vec<String>,
    },
}

pub fn generate_payloads(generator: PayloadGenerator) -> Result<Vec<String>, String> {
    let mut values = Vec::new();
    match generator {
        PayloadGenerator::Numbers { start, end, step } => {
            let start = start.parse::<i128>().map_err(|_| "Invalid range start")?;
            let end = end.parse::<i128>().map_err(|_| "Invalid range end")?;
            let step = step.parse::<i128>().map_err(|_| "Invalid range step")?;
            if step == 0 || (start < end && step < 0) || (start > end && step > 0) {
                return Err("Step must move toward the end and cannot be zero".into());
            }
            let mut value = start;
            while if step > 0 { value <= end } else { value >= end } {
                if values.len() >= 1000 {
                    return Err("A payload list may contain at most 1,000 values".into());
                }
                values.push(value.to_string());
                let Some(next) = value.checked_add(step) else {
                    break;
                };
                value = next;
            }
        }
        PayloadGenerator::Boundaries { bits, signed } => {
            if !matches!(bits, 8 | 16 | 32 | 64) {
                return Err("Choose 8, 16, 32, or 64 bits".into());
            }
            let (min, max) = if signed {
                (-(1i128 << (bits - 1)), (1i128 << (bits - 1)) - 1)
            } else {
                (0, (1i128 << bits) - 1)
            };
            let mut bounds = vec![min - 1, min, min + 1, -1, 0, 1, max - 1, max, max + 1];
            bounds.sort_unstable();
            bounds.dedup();
            values = bounds.into_iter().map(|n| n.to_string()).collect();
        }
        PayloadGenerator::Lengths {
            start,
            end,
            step,
            unit,
        } => {
            if step == 0 || start > end || end > 4096 || unit.is_empty() || unit.len() > 64 {
                return Err("Use increasing lengths up to 4,096, a positive step, and a nonempty unit of at most 64 bytes".into());
            }
            for n in (start..=end).step_by(step) {
                if values.len() >= 1000 || n.saturating_mul(unit.len()) > 4096 {
                    return Err("Payload count or byte length exceeds its limit".into());
                }
                values.push(unit.repeat(n));
            }
        }
        PayloadGenerator::Values { values: input } => values = input,
    }
    if values.is_empty()
        || values.len() > 1000
        || values
            .iter()
            .any(|v| v.len() > 4096 || v.contains(['\n', '\r']))
        || values.iter().map(String::len).sum::<usize>() > 4 * 1024 * 1024
    {
        return Err(
            "Use 1–1,000 single-line values, at most 4,096 bytes each and 4 MiB combined".into(),
        );
    }
    Ok(values)
}

#[cfg(test)]
mod payload_tests {
    use super::*;
    #[test]
    fn ranges_are_exact_and_bounded() {
        assert_eq!(
            generate_payloads(PayloadGenerator::Numbers {
                start: "9007199254740992".into(),
                end: "9007199254740994".into(),
                step: "1".into()
            })
            .unwrap(),
            vec!["9007199254740992", "9007199254740993", "9007199254740994"]
        );
        assert_eq!(
            generate_payloads(PayloadGenerator::Numbers {
                start: "3".into(),
                end: "1".into(),
                step: "-1".into()
            })
            .unwrap(),
            vec!["3", "2", "1"]
        );
        assert!(
            generate_payloads(PayloadGenerator::Numbers {
                start: "0".into(),
                end: "2000".into(),
                step: "1".into()
            })
            .is_err()
        );
        assert!(
            generate_payloads(PayloadGenerator::Numbers {
                start: "0".into(),
                end: "2".into(),
                step: "0".into()
            })
            .is_err()
        );
    }
    #[test]
    fn boundaries_include_invalid_values_and_lengths_include_empty() {
        let values = generate_payloads(PayloadGenerator::Boundaries {
            bits: 64,
            signed: false,
        })
        .unwrap();
        assert!(values.contains(&"18446744073709551616".into()));
        assert!(values.contains(&"-1".into()));
        assert_eq!(
            generate_payloads(PayloadGenerator::Lengths {
                start: 0,
                end: 2,
                step: 1,
                unit: "A".into()
            })
            .unwrap(),
            vec!["", "A", "AA"]
        );
        assert!(
            generate_payloads(PayloadGenerator::Lengths {
                start: 4096,
                end: 4096,
                step: 1,
                unit: "é".into()
            })
            .is_err()
        );
        assert!(
            generate_payloads(PayloadGenerator::Values {
                values: vec!["a\nb".into()]
            })
            .is_err()
        );
    }
}
