//! Field lookup shared by decoded history columns and other clients.
use serde_json::Value;

/// An exact decoder field name wins; otherwise follow dotted keys and array indices.
pub fn lookup<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    if let Some(value) = root.get(path) {
        return Some(value);
    }
    let mut value = root;
    for key in path.split(['.', '[', ']']).filter(|s| !s.is_empty()) {
        value = if let Some(object) = value.as_object() {
            object.get(key)?
        } else {
            value.get(key.parse::<usize>().ok()?)?
        };
    }
    Some(value)
}
#[cfg(test)]
mod tests {
    #[test]
    fn paths_are_data_not_expressions() {
        let value = serde_json::json!({"data":[{"slot":7}],"a.b":9});
        assert_eq!(
            super::lookup(&value, "data[0].slot"),
            Some(&serde_json::json!(7))
        );
        assert_eq!(super::lookup(&value, "a.b"), Some(&serde_json::json!(9)));
        assert!(super::lookup(&value, "data[-1]").is_none());
    }
}
