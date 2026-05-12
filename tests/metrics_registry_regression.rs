#[test]
fn counter_macro_identical_labels_accumulate_in_prometheus_registry() {
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let _guard = metrics::set_default_local_recorder(&recorder);

    for _ in 0..3 {
        metrics::counter!(
            "s3proxy_metrics_util_key_hasher_regression_total",
            "case" => "same_labels",
        )
        .increment(1);
    }

    let rendered = handle.render();
    let expected = r#"s3proxy_metrics_util_key_hasher_regression_total{case="same_labels"} 3"#;

    let matching: Vec<_> = rendered
        .lines()
        .filter(|line| {
            line.starts_with(
                r#"s3proxy_metrics_util_key_hasher_regression_total{case="same_labels"} "#,
            )
        })
        .collect();

    assert_eq!(matching, vec![expected], "rendered metrics:\n{rendered}");
}
