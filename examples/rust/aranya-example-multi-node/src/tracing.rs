//! Utilities for initializing tracing for the example.

use tracing::Metadata;
use tracing_subscriber::{
    layer::{Context, Filter},
    prelude::*,
    EnvFilter,
};

/// Example tracing filter.
struct DemoFilter {
    env_filter: EnvFilter,
    mod_path: String,
}

impl<S> Filter<S> for DemoFilter {
    fn enabled(&self, metadata: &Metadata<'_>, context: &Context<'_, S>) -> bool {
        if metadata.target().starts_with(&self.mod_path) {
            true
        } else {
            self.env_filter.enabled(metadata, context.clone())
        }
    }
}

// Initialize tracing for example executable.
pub fn init_tracing(mod_path: &str) {
    let filter = DemoFilter {
        env_filter: EnvFilter::try_from_env("ARANYA_EXAMPLE")
            .unwrap_or_else(|_| EnvFilter::new("off")),
        mod_path: mod_path.to_string(),
    };

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_file(false)
                .with_target(false)
                .compact()
                .with_filter(filter),
        )
        .init();
}
