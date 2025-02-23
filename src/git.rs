// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::{
    borrow::ToOwned as _,
    env,
    io::Write as _,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    str,
    string::String,
    vec::Vec,
};

use fs_err as fs;

#[track_caller]
pub fn assert_diff(expected_path: impl AsRef<Path>, actual: impl AsRef<[u8]>) {
    let actual = actual.as_ref();
    let expected_path = expected_path.as_ref();
    if !expected_path.is_file() {
        fs::create_dir_all(expected_path.parent().unwrap()).unwrap();
        fs::write(expected_path, "").unwrap();
    }
    let expected = fs::read(expected_path).unwrap();
    if expected != actual {
        if env::var_os("CI").is_some() {
            let color = if env::var_os("GITHUB_ACTIONS").is_some() {
                &["-c", "color.ui=always"][..]
            } else {
                &[]
            };
            let mut child = Command::new("git")
                .arg("--no-pager")
                .args(color)
                .args(["diff", "--no-index", "--"])
                .arg(expected_path)
                .arg("-")
                .stdin(Stdio::piped())
                .spawn()
                .unwrap();
            child.stdin.as_mut().unwrap().write_all(actual).unwrap();
            assert!(!child.wait().unwrap().success());
            // patch -p1 <<'EOF' ... EOF
            panic!(
                "assertion failed; please run test locally and commit resulting changes, or apply above diff as patch"
            );
        } else {
            fs::write(expected_path, actual).unwrap();
        }
    }
}

#[track_caller]
pub fn ls_files(dir: impl AsRef<Path>, filters: &[&str]) -> Vec<(String, PathBuf)> {
    let dir = dir.as_ref();
    let mut cmd = Command::new("git");
    cmd.arg("ls-files").args(filters).current_dir(dir);
    let output =
        cmd.output().unwrap_or_else(|e| panic!("could not execute process `{:?}`: {}", cmd, e));
    assert!(
        output.status.success(),
        "process didn't exit successfully: `{3:?}`:\n\nSTDOUT:\n{0}\n{1}\n{0}\n\nSTDERR:\n{0}\n{2}\n{0}\n",
        "-".repeat(60),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
        cmd,
    );
    str::from_utf8(&output.stdout)
        .unwrap()
        .lines()
        .map(str::trim)
        .filter_map(|f| {
            if f.is_empty() {
                return None;
            }
            let p = dir.join(f);
            if !p.exists() {
                return None;
            }
            Some((f.to_owned(), p))
        })
        .collect()
}
