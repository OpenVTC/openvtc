//! Three-way merge of one record's JSON.
//!
//! Two devices that edit *different* fields of one record both keep their
//! edit: archiving a community on one machine and starring it on another
//! converge to archived-and-starred. Only an edit to the *same* field on both
//! sides is a conflict, and that is reported, never hidden.
//!
//! A conflict resolves to the VTA's value. The VTA is the meeting point: the
//! first device to reach it wins, and every other device converges on that
//! rather than on whichever happened to sync last. The losing side is told.

use serde_json::{Map, Value};

/// Merge `local` and `remote` against their common `base`, recording the path
/// of every field both sides changed differently in `conflicts`.
///
/// `None` is "the record does not exist" on that side — a deletion, or a
/// record one side has never seen. `base` is `None` for a record this device
/// has never synced, which makes every disagreeing field a conflict: there is
/// no history to say which side moved.
#[must_use]
pub(crate) fn merge3(
    base: Option<&Value>,
    local: Option<&Value>,
    remote: Option<&Value>,
    path: &str,
    conflicts: &mut Vec<String>,
) -> Option<Value> {
    if local == remote {
        return local.cloned();
    }
    if base == local {
        return remote.cloned();
    }
    if base == remote {
        return local.cloned();
    }
    // Both sides moved. Objects merge field by field; anything else — a
    // scalar, an array, or a deletion against an edit — is a conflict.
    if let (Some(Value::Object(l)), Some(Value::Object(r))) = (local, remote) {
        let b = match base {
            Some(Value::Object(b)) => Some(b),
            _ => None,
        };
        let mut out = Map::new();
        let keys: std::collections::BTreeSet<&String> = l.keys().chain(r.keys()).collect();
        for k in keys {
            let child = format!("{path}/{k}");
            if let Some(v) = merge3(
                b.and_then(|b| b.get(k)),
                l.get(k),
                r.get(k),
                &child,
                conflicts,
            ) {
                out.insert(k.clone(), v);
            }
        }
        return Some(Value::Object(out));
    }
    conflicts.push(if path.is_empty() {
        "/".to_string()
    } else {
        path.to_string()
    });
    remote.cloned()
}

#[cfg(test)]
mod tests {
    use super::merge3;
    use serde_json::json;

    fn run(
        base: Option<serde_json::Value>,
        local: Option<serde_json::Value>,
        remote: Option<serde_json::Value>,
    ) -> (Option<serde_json::Value>, Vec<String>) {
        let mut conflicts = Vec::new();
        let merged = merge3(
            base.as_ref(),
            local.as_ref(),
            remote.as_ref(),
            "",
            &mut conflicts,
        );
        (merged, conflicts)
    }

    #[test]
    fn an_unchanged_side_takes_the_other_sides_edit() {
        let base = json!({"archived": false, "favourite": false});
        let remote = json!({"archived": true, "favourite": false});
        let (merged, conflicts) = run(Some(base.clone()), Some(base), Some(remote.clone()));
        assert_eq!(merged, Some(remote));
        assert!(conflicts.is_empty());
    }

    #[test]
    fn edits_to_different_fields_both_survive() {
        let base = json!({"archived": false, "favourite": false});
        let local = json!({"archived": false, "favourite": true});
        let remote = json!({"archived": true, "favourite": false});
        let (merged, conflicts) = run(Some(base), Some(local), Some(remote));
        assert_eq!(merged, Some(json!({"archived": true, "favourite": true})));
        assert!(conflicts.is_empty());
    }

    #[test]
    fn the_same_field_edited_both_ways_is_a_conflict_the_vta_wins() {
        let base = json!({"label": "a"});
        let local = json!({"label": "b"});
        let remote = json!({"label": "c"});
        let (merged, conflicts) = run(Some(base), Some(local), Some(remote));
        assert_eq!(merged, Some(json!({"label": "c"})));
        assert_eq!(conflicts, vec!["/label".to_string()]);
    }

    #[test]
    fn a_local_deletion_of_an_unchanged_record_stands() {
        let base = json!({"did": "x"});
        let (merged, conflicts) = run(Some(base.clone()), None, Some(base));
        assert_eq!(merged, None);
        assert!(conflicts.is_empty());
    }

    #[test]
    fn a_remote_deletion_against_a_local_edit_is_a_conflict() {
        let base = json!({"alias": "a"});
        let local = json!({"alias": "b"});
        let (merged, conflicts) = run(Some(base), Some(local), None);
        assert_eq!(merged, None);
        assert_eq!(conflicts, vec!["/".to_string()]);
    }

    #[test]
    fn a_field_added_on_one_side_with_no_history_is_kept() {
        let local = json!({"did": "x", "alias": "home"});
        let remote = json!({"did": "x", "label": "work"});
        let (merged, conflicts) = run(None, Some(local), Some(remote));
        assert_eq!(
            merged,
            Some(json!({"did": "x", "alias": "home", "label": "work"}))
        );
        assert!(conflicts.is_empty());
    }

    #[test]
    fn no_history_and_a_disagreeing_field_takes_the_vtas_value() {
        let (merged, conflicts) = run(
            None,
            Some(json!({"archived": false})),
            Some(json!({"archived": true})),
        );
        assert_eq!(merged, Some(json!({"archived": true})));
        assert_eq!(conflicts, vec!["/archived".to_string()]);
    }
}
