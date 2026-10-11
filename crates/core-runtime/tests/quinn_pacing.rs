//! Exercise the exact vendored pacer source in the workspace's normal CI suite.
//! No separate Quinn development dependencies or copied pacing implementation.
use std::time::{Duration, Instant};

#[allow(clippy::too_many_arguments)]
#[path = "../../../vendor/quinn-proto/src/connection/pacing.rs"]
mod pacing;
