// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::{format, mem, path::Path, string::String};

use fs_err as fs;

use crate::git::assert_diff;

#[track_caller]
pub fn sync_command_output_to_markdown(
    path: impl AsRef<Path>,
    marker: impl AsRef<str>,
    command: impl AsRef<str>,
    new: impl AsRef<str>,
) {
    let marker = marker.as_ref();
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
        &["```console\n$ ", command.as_ref(), "\n", new.as_ref(), "```\n"],
    );
}

/*
// #[test]
// fn sync_readme_to_doc() {
//     test_helper::doc::sync_readme_to_doc(env!("CARGO_MANIFEST_DIR"));
// }

#[track_caller]
pub fn sync_readme_to_doc(manifest_dir: impl AsRef<Path>) {
    if cfg!(miri) {
        return;
    }
    let manifest_dir = manifest_dir.as_ref();
    sync_gfm_to_markdown(
        manifest_dir.join("README.md"),
        manifest_dir.join("src/lib.rs"),
        "sync-readme-to-doc",
    );
}

#[track_caller]
pub fn sync_gfm_to_markdown(from: impl AsRef<Path>, to: impl AsRef<Path>, marker: impl AsRef<str>) {
    let from = from.as_ref();
    let to = to.as_ref();
    let marker = marker.as_ref();
    let start_marker = &*format!("<!-- {}:start -->", marker);
    let end_marker = &*format!("<!-- {}:end -->", marker);
    let new = {
        let path = from;
        let base = fs::read_to_string(path).unwrap();
        let mut out = String::with_capacity(base.capacity());
        let mut lines = base.lines();
        let mut start = false;
        while let Some(line) = lines.next() {
            if line == start_marker {
                if mem::replace(&mut start, true) {
                    panic!("multiple `{}` marker found in {}", start_marker, path.display());
                }
                convert_gfm(&mut lines, &mut out, end_marker, path);
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
            out
        } else {
            panic!("missing `{}` comment in {}", start_marker, path.display());
        }
    };
    insert(to, start_marker, end_marker, &[&new]);
}

#[track_caller]
fn convert_gfm(
    mut lines: &mut std::str::Lines<'_>,
    out: &mut String,
    end_marker: &str,
    path: &Path,
) {
    let mut end = false;
    'search_end: while let Some(line) = lines.next() {
        if line == end_marker {
            end = true;
            break 'search_end;
        }
        if let Some(alert) = line.strip_prefix("> [!").and_then(|line| line.strip_suffix("]")) {
            if !matches!(alert, "NOTE" | "TIP" | "IMPORTANT" | "WARNING" | "CAUTION") {
                panic!(
                    "unknown alert type '{}' found; please use one of the types listed in \
                     <https://docs.github.com/en/get-started/writing-on-github/getting-started-with-writing-and-formatting-on-github/basic-writing-and-formatting-syntax#alerts>",
                     alert
                );
            }
            out.push_str("<div class=\"rustdoc-alert rustdoc-alert-");
            for c in alert.chars() {
                out.push(c.to_ascii_lowercase());
            }
            out.push_str("\">\n\n");
            out.push_str("> **");
            if matches!(alert, "WARNING" | "CAUTION") {
                out.push_str("⚠ ");
            } else {
                out.push_str("ⓘ ");
            }
            let mut chars = alert.chars();
            out.push(chars.next().unwrap().to_ascii_uppercase());
            for c in chars {
                out.push(c.to_ascii_lowercase());
            }
            out.push_str("**\n>\n");
            for line in &mut lines {
                if !line.starts_with('>') && line.trim_ascii_start().is_empty() {
                    out.push_str("\n</div>\n");
                    if line == end_marker {
                        end = true;
                        break 'search_end;
                    }
                    out.push_str(line);
                    out.push('\n');
                    break;
                }
                out.push_str(line);
                out.push('\n');
            }
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    if !end {
        panic!("missing `{}` marker in {}", end_marker, path.display());
    }
}
*/

#[track_caller]
fn insert(path: &Path, start_marker: &str, end_marker: &str, new: &[&str]) {
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
