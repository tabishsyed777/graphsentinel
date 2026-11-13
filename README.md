# GraphSentinel

GraphSentinel is a local anomaly-detection lab for identity and resource access events. It turns user–resource activity into graph and temporal features, then ranks unusual events with Isolation Forest. It is designed for authorized logs and synthetic fixtures; it does not connect to an identity provider or block activity.

## Docker

```sh
docker build -t graphsentinel .
mkdir -p reports
docker run --rm -v "$PWD/samples:/data:ro" -v "$PWD/reports:/reports" graphsentinel /data/access_events.csv --output /reports/report.json
```

## Input columns

`timestamp,user,resource,source_ip,action` are required. Timestamps should be ISO-8601. The model derives user/resource degrees, new-edge flags, source fan-out, hour-of-day signals, and after-hours activity.

## Method and limits

The detector is unsupervised: it learns what is unusual in the supplied window, not what is malicious in general. Isolation Forest scores are relative to the input population. A flagged event is a triage lead; verify it against change tickets, identity context, and known service behavior. Small or highly seasonal datasets can produce unstable rankings.

The included data is synthetic. Its suspicious late-night burst is a fixture for checking the pipeline, not a measured security result.

## Browser preview

Open `index.html` for a dependency-free local preview. It reads a CSV in the browser and shows graph size, after-hours activity, and a lightweight novelty preview. The full Isolation Forest report runs through Python or Docker.

## License

MIT. See [LICENSE](LICENSE).
