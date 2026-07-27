//! ASN.1 concrete-syntax parser.
//!
//! ```no_run
//! use asn1_parser::{parse_source, SourceMap};
//! let mut map = SourceMap::new();
//! let src = std::fs::read_to_string("examples/poim/POIM-PDU-Description.asn").unwrap();
//! let file = map.add("POIM-PDU-Description.asn", src);
//! let module = parse_source(&map, file).unwrap();
//! println!("parsed module {}", module.name.value);
//! ```

#![deny(rust_2018_idioms)]

pub mod cst;
pub mod diagnostics;
mod grammar;
mod lexer;

pub use cst::*;
pub use diagnostics::{FileId, Location, ParseError, SourceFile, SourceMap, Span, Spanned};
pub use grammar::parse_module as parse_tokens;

/// Tokenize and parse the source text registered under `file` in `sources`.
pub fn parse_source(sources: &SourceMap, file: FileId) -> Result<Module, ParseError> {
    let source = sources
        .get(file)
        .ok_or_else(|| ParseError::new("file id not registered in source map", Span::DUMMY))?;
    let tokens = lexer::Lexer::new(file, &source.source).tokenize()?;
    grammar::parse_module(tokens)
}

/// Convenience: parse a source string that is not yet in a `SourceMap`.
///
/// Adds the file and returns both the source id and the parsed module so the
/// caller can render diagnostics with full context.
pub fn parse_text(
    sources: &mut SourceMap,
    path: impl Into<std::path::PathBuf>,
    source: String,
) -> Result<(FileId, Module), ParseError> {
    let file = sources.add(path, source);
    let module = parse_source(sources, file)?;
    Ok((file, module))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_str(src: &str) -> Module {
        let mut sm = SourceMap::new();
        let file = sm.add("test.asn", src.to_string());
        match parse_source(&sm, file) {
            Ok(m) => m,
            Err(e) => panic!("{}", e.render(&sm)),
        }
    }

    #[test]
    fn minimal_module() {
        let m = parse_str(
            r#"Foo DEFINITIONS AUTOMATIC TAGS ::= BEGIN
                Bar ::= INTEGER
            END"#,
        );
        assert_eq!(m.name.value, "Foo");
        assert_eq!(m.tag_default, TagDefault::Automatic);
        assert_eq!(m.assignments.len(), 1);
    }

    #[test]
    fn sequence_of_with_size_constraint() {
        let m = parse_str(
            r#"Foo DEFINITIONS AUTOMATIC TAGS ::= BEGIN
                Items ::= SEQUENCE (SIZE (1..8,...)) OF INTEGER
            END"#,
        );
        let Some(Assignment { kind: AssignmentKind::Type(t), .. }) =
            m.assignments.into_iter().next()
        else {
            panic!("expected type assignment");
        };
        match t.kind {
            TypeKind::SequenceOf(_) => {}
            _ => panic!("expected SEQUENCE OF"),
        }
        assert!(matches!(t.constraints.as_slice(), [Constraint::Size(_)]));
    }

    #[test]
    fn enumerated_with_extension() {
        let m = parse_str(
            r#"Foo DEFINITIONS AUTOMATIC TAGS ::= BEGIN
                Color ::= ENUMERATED { red, green (1), blue, ..., yellow (99) }
            END"#,
        );
        if let AssignmentKind::Type(t) = &m.assignments[0].kind {
            if let TypeKind::Enumerated { items, extensible, extension_items } = &t.kind {
                assert_eq!(items.len(), 3);
                assert!(*extensible);
                assert_eq!(extension_items.len(), 1);
            } else {
                panic!("expected enumerated");
            }
        } else {
            panic!("expected type");
        }
    }

    #[test]
    fn doc_comment_attaches_to_assignment() {
        let m = parse_str(
            r#"Foo DEFINITIONS AUTOMATIC TAGS ::= BEGIN
                /** the answer */
                answer ::= INTEGER
            END"#,
        );
        assert_eq!(m.assignments[0].doc.as_deref(), Some("the answer"));
    }

    #[test]
    fn object_identifier_value_assignment() {
        let m = parse_str(
            r#"Foo DEFINITIONS ::= BEGIN
                uicFcb OBJECT IDENTIFIER ::= { iso(1) identified-organization(3) dod(6) }
                uicFcbModules OBJECT IDENTIFIER ::= { uicFcb modules(0) }
                headerV1 OBJECT IDENTIFIER ::= { uicFcbModules header(1) v1(1) 0 }
            END"#,
        );
        assert_eq!(m.assignments.len(), 3);
        for a in &m.assignments {
            let AssignmentKind::Value { ty, value } = &a.kind else {
                panic!("expected value assignment for {}", a.name.value);
            };
            assert!(matches!(ty.kind, TypeKind::ObjectIdentifier));
            assert!(matches!(value, Value::Oid(_)), "expected OID value for {}", a.name.value);
        }
        let AssignmentKind::Value { value: Value::Oid(parts), .. } = &m.assignments[2].kind else {
            unreachable!()
        };
        assert_eq!(parts.len(), 4);
        assert_eq!(parts[0].name.as_ref().unwrap().value, "uicFcbModules");
        assert_eq!(parts[0].value, None);
        assert_eq!(parts[1].name.as_ref().unwrap().value, "header");
        assert_eq!(parts[1].value, Some(1));
        assert_eq!((parts[3].name.is_none(), parts[3].value), (true, Some(0)));
    }

    #[test]
    fn multi_word_and_constrained_value_assignment_types() {
        let m = parse_str(
            r#"Foo DEFINITIONS ::= BEGIN
                key OCTET STRING ::= '00FF'H
                flags BIT STRING ::= '1010'B
                limit INTEGER (0..10) ::= 7
                names SEQUENCE OF IA5String ::= { "a", "b" }
            END"#,
        );
        assert_eq!(m.assignments.len(), 4);
        let kinds: Vec<_> = m
            .assignments
            .iter()
            .map(|a| match &a.kind {
                AssignmentKind::Value { ty, .. } => &ty.kind,
                _ => panic!("expected value assignment for {}", a.name.value),
            })
            .collect();
        assert!(matches!(kinds[0], TypeKind::OctetString));
        assert!(matches!(kinds[1], TypeKind::BitString { .. }));
        assert!(matches!(kinds[2], TypeKind::Integer { .. }));
        assert!(matches!(kinds[3], TypeKind::SequenceOf(_)));
        let AssignmentKind::Value { ty, .. } = &m.assignments[2].kind else { unreachable!() };
        assert!(matches!(ty.constraints.as_slice(), [Constraint::ValueRange { .. }]));
    }

    #[test]
    fn object_set_assignment_still_recognized() {
        let m = parse_str(
            r#"Foo DEFINITIONS ::= BEGIN
                Blocks BLOCK-TYPE ::= { { Alpha IDENTIFIED BY alphaId }, ... }
            END"#,
        );
        let AssignmentKind::ObjectSet { class_name, set } = &m.assignments[0].kind else {
            panic!("expected object-set assignment");
        };
        assert_eq!(class_name.value, "BLOCK-TYPE");
        assert_eq!(set.elements.len(), 1);
        assert!(set.extensible);
    }

    #[test]
    fn imports_parsed() {
        let m = parse_str(
            r#"Foo DEFINITIONS AUTOMATIC TAGS ::= BEGIN
                IMPORTS
                    A, B FROM OtherMod {iso(1) mod(2)} WITH SUCCESSORS
                    C FROM ThirdMod
                ;
                X ::= A
            END"#,
        );
        assert_eq!(m.imports.len(), 2);
        assert_eq!(m.imports[0].symbols.len(), 2);
        assert_eq!(m.imports[0].with, Some(WithClause::Successors));
        assert_eq!(m.imports[1].with, None);
    }
}
