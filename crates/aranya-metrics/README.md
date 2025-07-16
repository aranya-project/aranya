# Aranya Metrics Collection

As with any project that grows large enough, Aranya is now able to collect various metrics to measure performance and find areas to target for improvement. This is accomplished in several ways:

-   Benchmarks that use `divan` to measure runtime and memory usage
-   The `aranya-metrics` crate that adds a harness on top of Aranya code that's representative of typical operation in order to see how the entire stack performs in that scenario. This includes cpu time, memory usage, and disk usage.

Future plans to support more information include:

-   Adding `metrics-rs` into more areas of Aranya to measure performance directly, with an optional recorder enabled to actually collect and display those values. Note that `metrics-rs` is designed to be lightweight enough that without a recorder, the performance impact is negligible.
-   Adding more granular metrics, using key-value pairs to report the data from specific daemon instances.
-   Using the above `divan` benchmarks, as well as [flame graphs](https://www.brendangregg.com/flamegraphs.html) to narrow down specific functions to augment with `#[fastrace::trace]` for measuring hot spots for improvements.
-   Adding a `metrics-rs` recorder and `fastrace` reporter to the daemon binary behind a feature flag to enable collecting metrics in production.

# Installation Instructions

Make sure [homebrew](https://brew.sh/) is installed, and then install the following packages:

-   [brew install prometheus](https://formulae.brew.sh/formula/prometheus), which installs [Prometheus](https://prometheus.io/), an open source metrics collection backend.
-   [brew install grafana](https://formulae.brew.sh/formula/grafana), which will install [Grafana](https://grafana.com/), an open source frontend to better visualize our metrics.

Download the correct package for the [`pushgateway`](https://prometheus.io/download/#pushgateway) since it's not available on `homebrew`, extract it, and `sudo cp pushgateway /usr/local/bin/` to install it as a tool.

Modify the Prometheus config file at `/opt/homebrew/etc/prometheus.yml` (or `/usr/local/etc/prometheus.yml`) to the following, to add `pushgateway` and `node_exporter` support:

```yaml
global:
    # By default, Prometheus will scrape data from our endpoints every 15 seconds
    scrape_interval: 15s

scrape_configs:
    # Prometheus runs on localhost:9090
    - job_name: "prometheus"
      static_configs:
          - targets: ["localhost:9090"]

    # Our pushgateway runs on localhost:9091, and we scrape it every 100ms
    - job_name: "pushgateway"
      static_configs:
          - targets: ["localhost:9091"]
      scrape_interval: 100ms
      honor_labels: true # Important
```

Finally, install the above as long-running services:

-   `brew services start prometheus`
-   `brew services start grafana`

Grafana can be accessed at `https://localhost:3000/`, sign-in by default is `admin:admin`.

# Collecting Metrics

The easiest way to do an `aranya-metrics` run is to simply call `cargo make metrics`, which will compile the daemon and this crate, spin up a `pushgateway`, run the example, and close everything.

After that's done and you have the job name (i.e. `aranya_demo_1751415368`), the easiest way to view the data is to go to Prometheus (`localhost:9090`), query for the job (`{job="aranya_demo_1751415368"}`), go to the graph tab, adjust the timescale to one where you can see the whole run, and you can click and drag to select a smaller range. Make sure to change the resolution to whatever your scrape interval is (the above config sets it to 100ms). You can then selectively look at categories using the list below the graph.

# Technical Details

Due to `sysinfo` only providing percentages of CPU usage at each refresh instead of raw user time/system time, we use `proc_pidinfo` on MacOS (falling back to `rusage` which only distinguishes between "self" and a generic "children") to grab CPU time and memory usage, using sysinfo for file I/O. `proc_pidinfo` and `rusage` both capture information "at the current moment" which means there isn't really a delta, whereas sysinfo's bytes_read/written is "since last refresh" so we have to aggregate it along with all previous deltas.

Basically, the "self" PID is an `aranya-client` instance (plus all metrics overhead), and since we use `Command::spawn()`, all `aranya-daemon` instances are children of the current PID which means we're allowed to access their information (`proc_pidinfo` can do weird stuff if you don't have permissions to access another process's info).

The way that we collect the metrics that are generated is using [Prometheus](https://prometheus.io/), an open source metrics collection framework. By default, Prometheus runs in a pull configuration, i.e. every so often Prometheus will scrape this process for metrics, which works for long running processes but isn't ideal for an isolated run. We instead use a separate tool provided by Prometheus called a [`pushgateway`](https://github.com/prometheus/pushgateway).

One caveat is that the `pushgateway` will continue to collect metrics until it's killed, so `cargo make metrics` spawns a `pushgateway` for the duration of the run. `aranya-metrics` generates a unique `job_name` using the current timestamp for easy querying.

`brew install protobuf` for TCP