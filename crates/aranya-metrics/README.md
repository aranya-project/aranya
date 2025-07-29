# Aranya Metrics Collection

As with any project that grows large enough, Aranya has a need for collecting benchmarks and other metrics to see if performance is improving or regressing over time and to get a sense for what could be improved. The `aranya-metrics` crate accomplishes this by providing a "harness" that measures memory, cpu, and disk usage and reporting it through one of several backends.

Future plans to collect more information include:

-   Adding `metrics-rs` into the daemon binary itself to collect additional metrics such as network usage and statistics about how the directed acyclic graph is performing. The provided exporter will need to be hidden behind a feature flag, and any metrics collection should compile out completely with it off.
-   Augmenting existing metrics with more information using key-value pairs, as well as reporting metrics for individual daemons.
-   Extending the above metrics harness with benchmarks using `divan` and [flame graphs](https://www.brendangregg.com/flamegraphs.html) to identify performance bottlenecks and functions that need to be annotated with `#[fastrace::trace]` for better measurement of hotspots.

# Prometheus Exporter

One of the supported metrics backends allows for communicating with a [Prometheus](https://prometheus.io/) instance. Note that with the way that Prometheus works, a datapoint is only created once the data is scraped, so any data created locally that gets overwritten before being scraped is lost. This can either be letting the main Prometheus backend scrape data from the exporter which is meant for longer running data, or using a `pushgateway` with a unique job name to easily filter out specific runs, which is meant more for short runs.

## Installation Instructions
You can get Prometheus through your favorite package manager; on MacOS it's preferred to use [homebrew](https://brew.sh/).

### MacOS Installation
Make sure homebrew is installed, and then run [brew install prometheus](https://formulae.brew.sh/formula/prometheus).

If you need the `pushgateway` binary, it's not available using homebrew, so'll have to [download it](https://prometheus.io/download/#pushgateway) from the Prometheus website, extract it, and install it using `sudo cp pushgateway /usr/local/bin/`. Note that when you first try to run the binary, MacOS will block it from running since it hasn't been notarized. After trying to run it once, follow the instructions on [Apple's website](https://support.apple.com/en-us/102445#openanyway) to allow the binary to run anyways.

You'll also have to modify the Prometheus config file at `/opt/homebrew/etc/prometheus.yml` (or `/usr/local/etc/prometheus.yml`), with your chosen scrape interval and `pushgateway` information if you're going that route. We've provided an [example file](prometheus.yml) for use with the exporter, which you can `sudo cp prometheus.yml /opt/homebrew/etc/prometheus.yml` to replace.

Once you've configured Prometheus, you'll want to set Prometheus to start automatically: `brew services start prometheus`. If you ran that command before changing the config, run `brew services restart prometheus`.

# Collecting Metrics

The easiest way to do an `aranya-metrics` run is to simply call `cargo make metrics`, which will compile the daemon and this crate, spin up a `pushgateway`, run the example, and close everything.

After that's done and you have the job name (i.e. `aranya_demo_1751415368`), the easiest way to view the data is to go to Prometheus (`localhost:9090`), query for the job (`{job="aranya_demo_1751415368"}`), go to the graph tab, adjust the timescale to one where you can see the whole run, and you can click and drag to select a smaller range. Make sure to change the resolution to whatever your scrape interval is (the above config sets it to 100ms). You can then selectively look at categories using the list below the graph.

# Technical Details

Due to `sysinfo` only providing percentages of CPU usage at each refresh instead of raw user time/system time, we use `proc_pidinfo` on MacOS (falling back to `rusage` which only distinguishes between "self" and a generic "children") to grab CPU time and memory usage, using sysinfo for file I/O. `proc_pidinfo` and `rusage` both capture information "at the current moment" which means there isn't really a delta, whereas sysinfo's bytes_read/written is "since last refresh" so we have to aggregate it along with all previous deltas.

Basically, the "self" PID is an `aranya-client` instance (plus all metrics overhead), and since we use `Command::spawn()`, all `aranya-daemon` instances are children of the current PID which means we're allowed to access their information (`proc_pidinfo` can do weird stuff if you don't have permissions to access another process's info).

The way that we collect the metrics that are generated is using [Prometheus](https://prometheus.io/), an open source metrics collection framework. By default, Prometheus runs in a pull configuration, i.e. every so often Prometheus will scrape this process for metrics, which works for long running processes but isn't ideal for an isolated run. We instead use a separate tool provided by Prometheus called a [`pushgateway`](https://github.com/prometheus/pushgateway).

One caveat is that the `pushgateway` will continue to collect metrics until it's killed, so `cargo make metrics` spawns a `pushgateway` for the duration of the run. `aranya-metrics` generates a unique `job_name` using the current timestamp for easy querying.

`brew install protobuf` for TCP
