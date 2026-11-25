// SPDX-License-Identifier: Apache-2.0 OR MIT

#![allow(clippy::must_use_candidate)]

use std::{
    borrow::ToOwned as _,
    io::{ErrorKind, Write as _},
    process::{Child, Command, ExitStatus, Output, Stdio},
    string::String,
    thread,
};

pub trait CommandExt {
    #[must_use]
    fn spawn_with_stdin(&mut self, stdin: impl AsRef<[u8]>) -> Child;
    fn assert_success(&mut self) -> AssertOutput;
    fn assert_failure(&mut self) -> AssertOutput;
}
impl CommandExt for Command {
    #[track_caller]
    fn spawn_with_stdin(&mut self, stdin: impl AsRef<[u8]>) -> Child {
        let mut child = self
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut pipe = child.stdin.take().unwrap();
        let stdin = stdin.as_ref();
        if !stdin.is_empty() {
            let stdin = stdin.to_owned();
            thread::spawn(move || {
                if let Err(e) = pipe.write_all(&stdin) {
                    // A child may exit or close stdin before consuming all of it.
                    if e.kind() != ErrorKind::BrokenPipe {
                        panic!("failed to write to child stdin: {}", e);
                    }
                }
            });
        }
        child
    }
    #[track_caller]
    fn assert_success(&mut self) -> AssertOutput {
        let output = AssertOutput::from(self.output().expect("failed to execute child"));
        if !output.status.success() {
            panic!(
                "assertion failed: `self.status.success()`:\n\nSTDOUT:\n{0}\n{1}\n{0}\n\nSTDERR:\n{0}\n{2}\n{0}\n",
                "-".repeat(60),
                output.stdout,
                output.stderr,
            );
        }
        output
    }
    #[track_caller]
    fn assert_failure(&mut self) -> AssertOutput {
        let output = AssertOutput::from(self.output().expect("failed to execute child"));
        if output.status.success() {
            panic!(
                "assertion failed: `!self.status.success()`:\n\nSTDOUT:\n{0}\n{1}\n{0}\n\nSTDERR:\n{0}\n{2}\n{0}\n",
                "-".repeat(60),
                output.stdout,
                output.stderr,
            );
        }
        output
    }
}

pub trait ChildExt {
    fn assert_success(self) -> AssertOutput;
    fn assert_failure(self) -> AssertOutput;
}
impl ChildExt for Child {
    #[track_caller]
    fn assert_success(self) -> AssertOutput {
        let output = AssertOutput::from(self.wait_with_output().expect("failed to wait on child"));
        if !output.status.success() {
            panic!(
                "assertion failed: `self.status.success()`:\n\nSTDOUT:\n{0}\n{1}\n{0}\n\nSTDERR:\n{0}\n{2}\n{0}\n",
                "-".repeat(60),
                output.stdout,
                output.stderr,
            );
        }
        output
    }
    #[track_caller]
    fn assert_failure(self) -> AssertOutput {
        let output = AssertOutput::from(self.wait_with_output().expect("failed to wait on child"));
        if output.status.success() {
            panic!(
                "assertion failed: `!self.status.success()`:\n\nSTDOUT:\n{0}\n{1}\n{0}\n\nSTDERR:\n{0}\n{2}\n{0}\n",
                "-".repeat(60),
                output.stdout,
                output.stderr,
            );
        }
        output
    }
}

pub struct AssertOutput {
    pub stdout: String,
    pub stderr: String,
    pub status: ExitStatus,
}

fn line_separated(lines: &str) -> impl Iterator<Item = &'_ str> {
    lines.lines().map(str::trim).filter(|line| !line.is_empty())
}

impl From<Output> for AssertOutput {
    fn from(output: Output) -> Self {
        Self {
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            status: output.status,
        }
    }
}

impl AssertOutput {
    #[track_caller]
    pub fn stdout_eq(&self, s: impl AsRef<str>) -> &Self {
        assert_eq!(self.stdout.trim(), s.as_ref().trim());
        self
    }
    /// Receives a line(`\n`)-separated list of patterns and asserts whether stdout contains each pattern.
    #[track_caller]
    pub fn stdout_contains(&self, pats: impl AsRef<str>) -> &Self {
        for pat in line_separated(pats.as_ref()) {
            if !self.stdout.contains(pat) {
                panic!(
                    "assertion failed: `self.stdout.contains(..)`:\n\nEXPECTED:\n{0}\n{2}\n{0}\n\nACTUAL:\n{0}\n{1}\n{0}\n",
                    "-".repeat(60),
                    self.stdout,
                    pat
                );
            }
        }
        self
    }
    /// Receives a line(`\n`)-separated list of patterns and asserts whether stdout contains each pattern.
    #[track_caller]
    pub fn stdout_not_contains(&self, pats: impl AsRef<str>) -> &Self {
        for pat in line_separated(pats.as_ref()) {
            if self.stdout.contains(pat) {
                panic!(
                    "assertion failed: `!self.stdout.contains(..)`:\n\nEXPECTED:\n{0}\n{2}\n{0}\n\nACTUAL:\n{0}\n{1}\n{0}\n",
                    "-".repeat(60),
                    self.stdout,
                    pat
                );
            }
        }
        self
    }

    #[track_caller]
    pub fn stderr_eq(&self, s: impl AsRef<str>) -> &Self {
        assert_eq!(self.stderr.trim(), s.as_ref().trim());
        self
    }
    /// Receives a line(`\n`)-separated list of patterns and asserts whether stderr contains each pattern.
    #[track_caller]
    pub fn stderr_contains(&self, pats: impl AsRef<str>) -> &Self {
        for pat in line_separated(pats.as_ref()) {
            if !self.stderr.contains(pat) {
                panic!(
                    "assertion failed: `self.stderr.contains(..)`:\n\nEXPECTED:\n{0}\n{2}\n{0}\n\nACTUAL:\n{0}\n{1}\n{0}\n",
                    "-".repeat(60),
                    self.stderr,
                    pat
                );
            }
        }
        self
    }
    /// Receives a line(`\n`)-separated list of patterns and asserts whether stderr contains each pattern.
    #[track_caller]
    pub fn stderr_not_contains(&self, pats: impl AsRef<str>) -> &Self {
        for pat in line_separated(pats.as_ref()) {
            if self.stderr.contains(pat) {
                panic!(
                    "assertion failed: `!self.stderr.contains(..)`:\n\nEXPECTED:\n{0}\n{2}\n{0}\n\nACTUAL:\n{0}\n{1}\n{0}\n",
                    "-".repeat(60),
                    self.stderr,
                    pat
                );
            }
        }
        self
    }
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use std::{sync::mpsc, time::Duration, vec};

    use super::*;

    #[test]
    #[cfg_attr(miri, ignore)] // Miri doesn't support std::process::Command: https://github.com/rust-lang/miri/issues/3374
    fn large_stdin() {
        let (tx, rx) = mpsc::channel();
        let h = thread::spawn(move || {
            let stdin = vec![b'x'; 4 * 1024 * 1024];
            let child = Command::new("cat").spawn_with_stdin(&stdin);
            let output = child.wait_with_output().unwrap();
            assert!(output.status.success());
            assert!(output.stdout == stdin);
            Command::new("false").spawn_with_stdin(&stdin).assert_failure();
            tx.send(()).unwrap();
        });
        rx.recv_timeout(Duration::from_secs(30)).unwrap();
        h.join().unwrap();
    }
}
