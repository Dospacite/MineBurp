//! Bounded, direction-independent connection alignment.
use mineburp_core::{Direction, PacketSummary};
use mineburp_project::{PacketQuery, ProjectStore};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};
use uuid::Uuid;

const CAP: usize = 20_000;
const EDIT_CAP: usize = 1024;
const NARROW: &str = "comparison limit exceeded; narrow the Traffic filter (maximum 20,000 packets per connection and 1,024 sequence edits per direction)";

#[derive(Debug, Serialize)]
pub struct ComparisonRow {
    pub a: Option<PacketSummary>,
    pub b: Option<PacketSummary>,
    pub kind: &'static str,
    pub size_delta: i64,
    pub first_difference: Option<usize>,
}
#[derive(Debug, Default, Serialize)]
pub struct NameComparison {
    pub name: String,
    pub a: usize,
    pub b: usize,
    pub differ: usize,
}
#[derive(Debug, Serialize)]
pub struct ConnectionComparison {
    pub rows: Vec<ComparisonRow>,
    pub names: Vec<NameComparison>,
}

fn key(packet: &PacketSummary) -> (mineburp_core::ProtocolState, Direction, &Option<String>) {
    (packet.state, packet.direction, &packet.name)
}

type AlignmentPair = (Option<usize>, Option<usize>);

/// Myers shortest edit script, with bounded trace memory and work.
#[allow(
    clippy::many_single_char_names,
    clippy::similar_names,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "Myers coordinates are bounded by CAP and EDIT_CAP"
)]
fn align<T: Eq>(a: &[T], b: &[T]) -> Result<Vec<AlignmentPair>, String> {
    if a.len() > CAP || b.len() > CAP {
        return Err(NARROW.into());
    }
    let width = 2 * EDIT_CAP + 3;
    let origin = EDIT_CAP + 1;
    let mut v = vec![0usize; width];
    let mut trace = Vec::new();
    for d in 0..=EDIT_CAP {
        trace.push(v.clone());
        for k in (origin - d..=origin + d).step_by(2) {
            let mut x = if k == origin - d || (k != origin + d && v[k - 1] < v[k + 1]) {
                v[k + 1]
            } else {
                v[k - 1] + 1
            };
            let mut y = (x as isize - (k as isize - origin as isize)) as usize;
            while x < a.len() && y < b.len() && a[x] == b[y] {
                x += 1;
                y += 1;
            }
            v[k] = x;
            if x >= a.len() && y >= b.len() {
                let (mut x, mut y) = (a.len(), b.len());
                let mut result = Vec::new();
                for depth in (0..=d).rev() {
                    if depth == 0 {
                        while x > 0 && y > 0 {
                            x -= 1;
                            y -= 1;
                            result.push((Some(x), Some(y)));
                        }
                        break;
                    }
                    let previous = &trace[depth];
                    let k = (origin as isize + x as isize - y as isize) as usize;
                    let pk = if k == origin - depth
                        || (k != origin + depth && previous[k - 1] < previous[k + 1])
                    {
                        k + 1
                    } else {
                        k - 1
                    };
                    let px = previous[pk];
                    let py = (px as isize - (pk as isize - origin as isize)) as usize;
                    while x > px && y > py {
                        x -= 1;
                        y -= 1;
                        result.push((Some(x), Some(y)));
                    }
                    if depth > 0 {
                        if x == px {
                            y -= 1;
                            result.push((None, Some(y)));
                        } else {
                            x -= 1;
                            result.push((Some(x), None));
                        }
                    }
                }
                result.reverse();
                return Ok(result);
            }
        }
    }
    Err(NARROW.into())
}

#[allow(
    clippy::too_many_lines,
    reason = "bounded load, alignment, and classification share a single operation budget"
)]
pub fn compare_connections(
    store: &ProjectStore,
    a: Uuid,
    b: Uuid,
    query: &PacketQuery,
) -> Result<ConnectionComparison, String> {
    let deadline = Instant::now() + Duration::from_secs(30);
    let check = || {
        if Instant::now() > deadline {
            Err("comparison read budget exceeded; narrow the filter".to_string())
        } else {
            Ok(())
        }
    };
    let load = |id| -> Result<Vec<PacketSummary>, String> {
        let mut q = query.clone();
        q.connection_id = Some(id);
        q.offset = 0;
        q.limit = 500;
        q.before_id = None;
        q.after_id = None;
        q.oldest_first = true;
        let mut rows = Vec::new();
        loop {
            check()?;
            let page = store.query_history_page(&q).map_err(|e| e.to_string())?;
            if page.is_empty() {
                break;
            }
            q.after_id = page.last().map(|p| p.id);
            rows.extend(page);
            if rows.len() > CAP {
                return Err(NARROW.into());
            }
        }
        Ok(rows)
    };
    let left = load(a)?;
    let right = load(b)?;
    let mut rows = Vec::new();
    let mut names = BTreeMap::<String, NameComparison>::new();
    for direction in [Direction::ClientToServer, Direction::ServerToClient] {
        let a: Vec<_> = left.iter().filter(|p| p.direction == direction).collect();
        let b: Vec<_> = right.iter().filter(|p| p.direction == direction).collect();
        let ak: Vec<_> = a.iter().map(|p| key(p)).collect();
        let bk: Vec<_> = b.iter().map(|p| key(p)).collect();
        for (i, j) in align(&ak, &bk)? {
            check()?;
            let a = i.map(|i| a[i]);
            let b = j.map(|j| b[j]);
            let mut first_difference = None;
            let kind = if let (Some(a), Some(b)) = (a, b) {
                let max = a.size.max(b.size);
                for offset in (0..max).step_by(256 * 1024) {
                    check()?;
                    let aw = store
                        .packet_window(a.id, offset, 256 * 1024)
                        .map_err(|e| e.to_string())?
                        .ok_or("packet removed during comparison")?;
                    let bw = store
                        .packet_window(b.id, offset, 256 * 1024)
                        .map_err(|e| e.to_string())?
                        .ok_or("packet removed during comparison")?;
                    if aw.bytes != bw.bytes {
                        first_difference = Some(
                            offset
                                + aw.bytes
                                    .iter()
                                    .zip(bw.bytes.iter())
                                    .position(|(a, b)| a != b)
                                    .unwrap_or(aw.bytes.len().min(bw.bytes.len())),
                        );
                        break;
                    }
                }
                if first_difference.is_some() {
                    "changed"
                } else {
                    "identical"
                }
            } else if a.is_some() {
                "only_a"
            } else {
                "only_b"
            };
            let name = a
                .or(b)
                .and_then(|p| p.name.clone())
                .unwrap_or_else(|| "<unnamed>".into());
            let aggregate = names.entry(name.clone()).or_insert_with(|| NameComparison {
                name,
                ..Default::default()
            });
            aggregate.a += usize::from(a.is_some());
            aggregate.b += usize::from(b.is_some());
            aggregate.differ += usize::from(kind != "identical");
            rows.push(ComparisonRow {
                a: a.cloned(),
                b: b.cloned(),
                kind,
                size_delta: b.map_or(0, |p| i64::try_from(p.size).unwrap_or(i64::MAX))
                    - a.map_or(0, |p| i64::try_from(p.size).unwrap_or(i64::MAX)),
                first_difference,
            });
        }
    }
    Ok(ConnectionComparison {
        rows,
        names: names.into_values().collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sequence_edits() {
        assert_eq!(
            align(&[1, 2], &[1, 2]).unwrap(),
            vec![(Some(0), Some(0)), (Some(1), Some(1))]
        );
        for (a, b) in [
            (vec![1, 2], vec![1, 3, 2]),
            (vec![1, 3, 2], vec![1, 2]),
            (vec![1, 2], vec![2, 1]),
            (vec![], vec![1]),
        ] {
            let rows = align(&a, &b).unwrap();
            assert_eq!(
                rows.iter()
                    .filter_map(|(i, _)| i.map(|i| a[i]))
                    .collect::<Vec<_>>(),
                a
            );
            assert_eq!(
                rows.iter()
                    .filter_map(|(_, i)| i.map(|i| b[i]))
                    .collect::<Vec<_>>(),
                b
            );
            for (i, j) in rows {
                if let (Some(i), Some(j)) = (i, j) {
                    assert_eq!(a[i], b[j]);
                }
            }
        }
        assert_eq!(align(&vec![0; CAP], &vec![0; CAP]).unwrap().len(), CAP);
        assert!(align(&vec![0; CAP + 1], &[0]).is_err());
        assert!(align(&vec![0; 1025], &vec![1; 1025]).is_err());
    }
}
