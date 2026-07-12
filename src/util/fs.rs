//! Utility functions related to file I/O.

use std::{fmt, io, path::Path};

use fs_err::tokio::read;
use tracing::instrument;

/// Read whole file into new buffer.
///
/// # Errors
///
/// Returns `Err` if there was an I/O error while opening or reading the file.
#[instrument(err)]
pub(crate) async fn read_file(path: impl AsRef<Path> + fmt::Debug) -> Result<Vec<u8>, io::Error> {
    read(path).await
}
