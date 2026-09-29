//! CloudWatch Embedded Metric Format: metrics written as structured log lines, with no
//! PutMetricData calls.
//!
//! Every metric is published with no dimensions (what the alarms watch) and, when dimensions
//! are given, also broken down by them (for the dashboard).

use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value, json};

fn namespace() -> String {
    std::env::var("METRICS_NAMESPACE").unwrap_or_else(|_| "CorroDemo".to_owned())
}

pub fn build(name: &str, value: f64, dims: &[(&str, &str)]) -> Value {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let mut dimension_sets = vec![Vec::<&str>::new()];
    if !dims.is_empty() {
        dimension_sets.push(dims.iter().map(|(k, _)| *k).collect());
    }
    let mut record = Map::new();
    record.insert(
        "_aws".into(),
        json!({
            "Timestamp": ts,
            "CloudWatchMetrics": [{
                "Namespace": namespace(),
                "Dimensions": dimension_sets,
                "Metrics": [{ "Name": name, "Unit": "Count" }],
            }],
        }),
    );
    record.insert(name.into(), json!(value));
    for (k, v) in dims {
        record.insert((*k).into(), json!(v));
    }
    Value::Object(record)
}

/// Writes one EMF line to stdout, where the Lambda runtime sends it to CloudWatch Logs.
pub fn count(name: &str, dims: &[(&str, &str)]) {
    println!("{}", build(name, 1.0, dims));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emits_undimensioned_and_dimensioned_sets() {
        let v = build("AuthzDenied", 1.0, &[("reason", "not_member")]);
        let dims = &v["_aws"]["CloudWatchMetrics"][0]["Dimensions"];
        assert_eq!(dims, &json!([[], ["reason"]]));
        assert_eq!(v["AuthzDenied"], json!(1.0));
        assert_eq!(v["reason"], json!("not_member"));
    }

    #[test]
    fn no_dims_means_one_empty_set() {
        let v = build("AuditWriteFailed", 1.0, &[]);
        assert_eq!(v["_aws"]["CloudWatchMetrics"][0]["Dimensions"], json!([[]]));
    }
}
