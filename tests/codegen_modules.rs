// SPDX-License-Identifier: Apache-2.0 OR MIT

#![cfg(feature = "codegen")]

use std::{fs, path::Path, process};

use test_helper::codegen::{AssertImplConfig, TrackSizeConfig, gen_assert_impl, gen_track_size};

#[test]
fn module_paths_and_cfgs() {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("codegen-{}", process::id()));
    for (path, contents) in [
        (
            "lib.rs",
            r#"#[cfg(unix)] mod left;
               mod right { pub mod leaf; }
               #[cfg_attr(feature = "alt", path = "alt_impl.rs")] mod backend;"#,
        ),
        ("left/mod.rs", "#![cfg(target_pointer_width = \"64\")] pub mod leaf;"),
        (
            "left/leaf.rs",
            r#"pub mod inline {
                #[cfg(feature = "extra")] pub struct Shared;
                pub struct Sibling;
            }"#,
        ),
        ("right/leaf.rs", "pub struct Shared;"),
        ("backend.rs", "pub struct DefaultImpl;"),
        (
            "alt_impl.rs",
            "#[cfg_attr(unix, derive(Debug), cfg_attr(debug_assertions, repr(C), cfg(test)))]
               pub struct AltImpl;",
        ),
        ("orphan.rs", "pub struct Orphan;"),
    ] {
        let path = root.join("src").join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }
    let (_, impls) = gen_assert_impl(&root, AssertImplConfig {
        exclude: &[],
        not_send: &[],
        not_sync: &[],
        not_unpin: &[],
        not_unwind_safe: &[],
        not_ref_unwind_safe: &[],
    });
    let (_, sizes) = gen_track_size(&root, TrackSizeConfig { exclude: &[] });
    fs::remove_dir_all(root).unwrap();

    let expected = [
        (
            "left::leaf::inline::Shared",
            r#"#[cfg(unix)]#[cfg(target_pointer_width="64")]#[cfg(feature="extra")]"#,
        ),
        ("left::leaf::inline::Sibling", r#"#[cfg(unix)]#[cfg(target_pointer_width="64")]"#),
        ("right::leaf::Shared", ""),
        ("backend::DefaultImpl", r#"#[cfg(not(feature="alt"))]"#),
        (
            "backend::AltImpl",
            r#"#[cfg(feature="alt")]#[cfg_attr(unix,cfg_attr(debug_assertions,cfg(test)))]"#,
        ),
    ];
    for (generated, call) in
        [(impls, "test_helper::assert_value!(crate::"), (sizes, "write_size::<crate::")]
    {
        let generated = generated.to_string().replace(' ', "");
        let calls: Vec<_> = generated.split(';').filter_map(|s| s.split_once(call)).collect();
        assert_eq!(calls.len(), expected.len(), "{generated}");
        for (path, gates) in expected {
            let (attrs, _) = calls.iter().find(|(_, args)| args.starts_with(path)).unwrap();
            assert_eq!(*attrs, gates, "{path}");
        }
    }
}
