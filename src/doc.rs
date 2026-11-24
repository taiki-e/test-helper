// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::{
    format, mem,
    path::Path,
    string::String,
    sync::{Mutex, PoisonError},
};

use fs_err as fs;

use crate::{git::assert_diff, once_lock::OnceLock};

#[track_caller]
pub fn sync_command_output_to_markdown(
    path: impl AsRef<Path>,
    marker: impl AsRef<str>,
    command: impl AsRef<str>,
    new: impl AsRef<str>,
) {
    let marker = marker.as_ref();
    let new = new.as_ref();
    let fence = if new.is_empty() || new.ends_with('\n') { "```\n" } else { "\n```\n" };
    /*
    Inserts:

    ```console\n
    $ <command>\n
    <new>
    ```\n
    */
    insert(
        path.as_ref(),
        &format!("<!-- {}:start -->", marker),
        &format!("<!-- {}:end -->", marker),
        &["```console\n$ ", command.as_ref(), "\n", new, fence],
    );
}

#[track_caller]
fn insert(path: &Path, start_marker: &str, end_marker: &str, new: &[&str]) {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new(); // prevent concurrent marker updates
    let _guard = LOCK.get_or_init(|| Mutex::new(())).lock().unwrap_or_else(PoisonError::into_inner);
    let base = fs::read_to_string(path).unwrap();
    let mut out = String::with_capacity(base.capacity());
    let mut lines = base.lines();
    let mut start = false;
    let mut end = false;
    while let Some(line) = lines.next() {
        out.push_str(line);
        out.push('\n');
        if line == start_marker {
            if mem::replace(&mut start, true) {
                panic!("multiple `{}` marker found in {}", start_marker, path.display());
            }
            for new in new {
                out.push_str(new);
            }
            for line in &mut lines {
                if line == end_marker {
                    out.push_str(line);
                    out.push('\n');
                    end = true;
                    break;
                }
            }
            if !end {
                panic!("missing `{}` marker in {}", end_marker, path.display());
            }
        } else if line == end_marker {
            panic!(
                "`{}` marker without corresponding `{}` marker found in {}",
                end_marker,
                start_marker,
                path.display()
            );
        }
    }
    if start {
        assert_diff(path, out);
    } else {
        panic!("missing `{}` marker in {}", start_marker, path.display());
    }
}
