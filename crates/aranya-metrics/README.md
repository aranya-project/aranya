# Aranya Metrics Collection

As with any project that grows large enough, Aranya has a need for collecting benchmarks and other metrics to see if performance is improving or regressing over time and to get a sense for what could be improved. The `aranya-metrics` crate accomplishes this by providing a "harness" that measures memory, cpu, and disk usage and reporting it through one of several backends.

Future plans to collect more information include:

-   Adding `metrics-rs` into the daemon binary itself to collect additional metrics such as network usage and statistics about how the directed acyclic graph is performing. The provided exporter will need to be hidden behind a feature flag, and any metrics collection should compile out completely with it off.
-   Augmenting existing metrics with more information using key-value pairs, as well as reporting metrics for individual daemons.
-   Extending the above metrics harness with benchmarks using `divan` and [flame graphs](https://www.brendangregg.com/flamegraphs.html) to identify performance bottlenecks and functions that need to be annotated with `#[fastrace::trace]` for better measurement of hotspots.

## Prometheus Exporter

One of the supported metrics backends allows for communicating with a [Prometheus](https://prometheus.io/) instance. Note that with the way that Prometheus works, a datapoint is only created once the data is scraped, so any data created locally that gets overwritten before being scraped is lost. This can either be letting the main Prometheus backend scrape data from the exporter which is meant for longer running data, or using a `pushgateway` with a unique job name to easily filter out specific runs, which is meant for shorter runs.

### Installation Instructions
You can get Prometheus through your favorite package manager; on MacOS it's preferred to use [homebrew](https://brew.sh/).

#### MacOS Installation
Make sure homebrew is installed, and then run [brew install prometheus](https://formulae.brew.sh/formula/prometheus).

If you need the `pushgateway` binary, it's not available using homebrew, so'll have to [download it](https://prometheus.io/download/#pushgateway) from the Prometheus website, extract it, and install it using `sudo cp pushgateway /usr/local/bin/`. Note that when you first try to run the binary, MacOS will block it from running since it hasn't been notarized. After trying to run it once, follow the instructions on [Apple's website](https://support.apple.com/en-us/102445#openanyway) to allow the binary to run anyways.

You'll also have to modify the Prometheus config file at `/opt/homebrew/etc/prometheus.yml` (or `/usr/local/etc/prometheus.yml`), with your chosen scrape interval and `pushgateway` information if you're going that route. We've provided an [example file](prometheus.yml) for use with the exporter, which you can `sudo cp prometheus.yml /opt/homebrew/etc/prometheus.yml` to replace.

Once you've configured Prometheus, you'll want to set Prometheus to start automatically: `brew services start prometheus`. If you ran that command before changing the config, run `brew services restart prometheus`.

## DogStatsD Exporter
Another supported backend is using `dogstatsd` to export metrics to a Datadog Agent.

<!-- TODO(nikki): more information about this exporter -->

## TCP Exporter
`aranya-metrics` also supports exporting data over plaintext TCP (meaning no encryption). This works by serializing data using [`protobuf`](https://protobuf.dev/) and sending it to any connected client.

### Installation Instructions
All you need to do is connect to the configured TCP address/port and listen for data coming back. You'll need to have `protoc` installed to be able to compile the exporter, as well as having the corresponding [protobuf file](https://github.com/metrics-rs/metrics/blob/main/metrics-exporter-tcp/proto/event.proto) to be able to decode the serialized data, but this allows sending metrics to clients written using many different programming languages. See your language's ecosystem for more support on protobuf, as well as the documentation website linked above.

## MacOS Installation
Make sure homebrew is installed, and then simply run [brew install protobuf](https://formulae.brew.sh/formula/protobuf).

## Collecting Metrics

The easiest way to do an `aranya-metrics` run is to simply run `cargo make metrics`, which will compile the daemon and this crate, and then log metrics to the command line.

Alternatively, you can run `cargo make metrics-prometheus` which will spin up a `pushgateway` and run the example. Once that's done and you have the job name (i.e. `aranya_demo_1751415368`), the easiest way to view the data is to go to Prometheus (`localhost:9090`), query for the job (`{job="aranya_demo_1751415368"}`), go to the graph tab, adjust the timescale to one where you can see the whole run, and you can click and drag to select a smaller range. Make sure to change the resolution to whatever your scrape interval is (the above config sets it to 100ms). You can then filter specific metrics using the list below the graph.

## Technical Details

Due to `sysinfo` only providing percentages of CPU usage at each refresh instead of raw user time/system time, we use `proc_pidinfo` on MacOS to grab the raw CPU time and memory usage, using sysinfo for file I/O. `proc_pidinfo` captures information "at the current moment" which means there isn't really a delta, whereas sysinfo's bytes_read/written is "since last refresh" so we have to aggregate it along with all previous deltas.

The PIDs being tracked include "client", which is an `aranya-client` instance (plus metrics overhead), as well as five `aranya-daemon` instances ("owner", "admin", "operator", "member_a", and "member_b"), which are created as sub-processes using `Command::spawn()` (`proc_pidinfo` can do weird stuff if you don't have permissions to access another process's info).

As mentioned above, Prometheus works using a pull/scrape model and `pushgateway` will push metrics to Prometheus every tick, but that means that the scrape interval dictates the "resolution" of the data, data can be overwritten if the metrics are run twice before they get scraped. `pushgateway` also continues to push datapoints until metrics time out, so configuring an adequate timeout using `aranya-metrics`'s config is important. As mentioned above, we also use a unique `job_name` using the current timestamp to make it easy to query for.

<!-- TODO(nikki): technical details for datadog and TCP -->
