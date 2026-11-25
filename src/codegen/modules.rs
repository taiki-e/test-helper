// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::{
    io,
    path::{Path, PathBuf},
    string::ToString as _,
    vec::Vec,
};

use fs_err as fs;
use syn::{Attribute, Ident, Item, ext::IdentExt as _};

use super::{GEN_TESTS_DIR, cfg};

pub(super) fn visit(crate_root: &Path, f: impl FnMut(&Item, &[Ident], &[Attribute], &Path)) {
    let mut visitor = Visitor {
        f,
        module: Vec::new(),
        files: Vec::new(),
        generated: fs::canonicalize(crate_root.join(GEN_TESTS_DIR)).unwrap(),
    };
    let src = crate_root.join("src");
    visitor.file(&src.join("lib.rs"), &src, &mut Vec::new());
}

struct Visitor<F> {
    f: F,
    module: Vec<Ident>,
    files: Vec<PathBuf>,
    generated: PathBuf,
}

impl<F: FnMut(&Item, &[Ident], &[Attribute], &Path)> Visitor<F> {
    fn file(&mut self, file: &Path, children: &Path, gates: &mut Vec<Attribute>) {
        let canonical = match fs::canonicalize(file) {
            Ok(path) => path,
            // An optional source or one of our own outputs may not exist yet.
            Err(e)
                if e.kind() == io::ErrorKind::NotFound
                    && (!gates.is_empty() || self.is_output(file)) =>
            {
                return;
            }
            Err(e) => panic!("{}", e),
        };
        if self.is_output(file) || self.is_output(&canonical) {
            return;
        }
        if self.files.contains(&canonical) {
            // Mutually exclusive cfg branches can include one another in the source tree.
            assert!(!gates.is_empty(), "circular module inclusion at {}", file.display());
            return;
        }
        self.files.push(canonical);
        let source = fs::read_to_string(file).unwrap();
        let ast = syn::parse_file(&source)
            .unwrap_or_else(|e| panic!("could not parse {}: {}", file.display(), e));
        let inherited = gates.len();
        gates.extend(cfg::cfg_attrs(&ast.attrs));
        self.items(&ast.items, file, file.parent().unwrap(), children, gates);
        gates.truncate(inherited);
        self.files.pop();
    }

    fn is_output(&self, path: &Path) -> bool {
        matches!(
            path.file_name().and_then(|s| s.to_str()),
            Some("assert_impl.rs" | "track_size.rs")
        ) && fs::canonicalize(path.parent().unwrap()).ok().as_deref() == Some(&self.generated)
    }

    fn items(
        &mut self,
        items: &[Item],
        file: &Path,
        path_base: &Path,
        children: &Path,
        gates: &mut Vec<Attribute>,
    ) {
        for item in items {
            let attrs = match item {
                Item::Mod(i) => &i.attrs,
                Item::Macro(i) => &i.attrs,
                Item::Struct(i) => &i.attrs,
                Item::Enum(i) => &i.attrs,
                Item::Union(i) => &i.attrs,
                Item::Type(i) => &i.attrs,
                _ => continue,
            };
            let inherited = gates.len();
            gates.extend(cfg::cfg_attrs(attrs));
            match item {
                Item::Mod(m) => {
                    let name = m.ident.unraw().to_string();
                    self.module.push(m.ident.clone());
                    for (path, branch) in cfg::module_paths(attrs) {
                        let outer = gates.len();
                        gates.extend(branch);
                        // In foo.rs the default child directory is foo/, but a #[path]
                        // is relative to the directory containing foo.rs itself.
                        let dir = match &path {
                            Some(path) => path_base.join(path),
                            None => children.join(&name),
                        };
                        if let Some((_, items)) = &m.content {
                            self.items(items, file, &dir, &dir, gates);
                        } else if path.is_some() {
                            // A file selected by #[path] owns its parent directory like mod.rs.
                            self.file(&dir, dir.parent().unwrap(), gates);
                        } else {
                            let flat = dir.with_extension("rs");
                            let nested = dir.join("mod.rs");
                            if nested.is_file() {
                                assert!(
                                    !flat.is_file(),
                                    "ambiguous module files {} and {}",
                                    flat.display(),
                                    nested.display()
                                );
                                self.file(&nested, &dir, gates);
                            } else {
                                self.file(&flat, &dir, gates);
                            }
                        }
                        gates.truncate(outer);
                    }
                    self.module.pop();
                }
                Item::Macro(m) => {
                    if let Ok(ast) = syn::parse2::<syn::File>(m.mac.tokens.clone()) {
                        gates.extend(cfg::cfg_attrs(&ast.attrs));
                        self.items(&ast.items, file, path_base, children, gates);
                    }
                }
                _ => (self.f)(item, &self.module, gates, file),
            }
            gates.truncate(inherited);
        }
    }
}
