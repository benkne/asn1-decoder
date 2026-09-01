//! Lowered, resolved intermediate representation of ASN.1 modules.
//!
//! The parser crate produces a [`asn1_parser::Module`] per input file; this crate
//! flattens a slice of those modules into an [`IrProgram`] that the codegen and
//! visualization crates consume. Lowering keeps source spans and doc comments but
//! normalizes the type tree so downstream consumers don't have to re-derive
//! structural information from the CST.

#![deny(rust_2018_idioms)]

use std::collections::HashMap;

use asn1_parser as cst;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Root of the lowered representation — one entry per input module.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct IrProgram {
    pub modules: Vec<IrModule>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct IrModule {
    pub name: String,
    pub oid: Option<Vec<IrOidPart>>,
    pub imports: Vec<IrImport>,
    pub items: Vec<IrItem>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct IrOidPart {
    pub name: Option<String>,
    pub value: Option<i64>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct IrImport {
    pub symbols: Vec<String>,
    pub from_module: String,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum IrItem {
    Type(IrTypeDef),
    Value(IrValueDef),
    ObjectClass(IrObjectClassDef),
    ObjectSet(IrObjectSetDef),
    Object(IrObjectDef),
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct IrTypeDef {
    pub name: String,
    pub doc: Option<String>,
    pub ty: IrType,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct IrValueDef {
    pub name: String,
    pub doc: Option<String>,
    pub ty: IrType,
    pub value: String,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct IrObjectClassDef {
    pub name: String,
    pub doc: Option<String>,
    pub fields: Vec<IrClassField>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum IrClassField {
    Type { name: String, optional: bool },
    Value { name: String, ty: IrType, optional: bool, unique: bool },
    VariableType { name: String, field_path: Vec<String>, optional: bool },
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct IrObjectSetDef {
    pub name: String,
    pub class_name: String,
    pub extensible: bool,
    pub members: usize,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct IrObjectDef {
    pub name: String,
    pub class_name: String,
    pub fields: Vec<IrObjectFieldBinding>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct IrObjectFieldBinding {
    pub name: String,
    pub binding: IrObjectFieldValue,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum IrObjectFieldValue {
    Type(IrType),
    Value(String),
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum IrType {
    Boolean,
    Integer {
        named_numbers: Vec<(String, i128)>,
        constraints: Vec<IrConstraint>,
    },
    Real,
    Null,
    BitString {
        named_bits: Vec<(String, i128)>,
        constraints: Vec<IrConstraint>,
    },
    OctetString {
        constraints: Vec<IrConstraint>,
    },
    ObjectIdentifier,
    RelativeOid,
    CharString {
        kind: IrCharKind,
        constraints: Vec<IrConstraint>,
    },
    UtcTime,
    GeneralizedTime,
    Enumerated {
        items: Vec<IrEnumItem>,
        extensible: bool,
    },
    Sequence(IrStruct),
    Set(IrStruct),
    SequenceOf {
        element: Box<IrType>,
        constraints: Vec<IrConstraint>,
    },
    SetOf {
        element: Box<IrType>,
        constraints: Vec<IrConstraint>,
    },
    Choice(IrChoice),
    /// Resolved or unresolved named reference.
    Reference {
        module: Option<String>,
        name: String,
    },
    /// `CLASS.&field` — open type, left unresolved.
    Open {
        description: String,
    },
    /// Any fallback that we parsed structurally but don't model semantically.
    Any,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum IrCharKind {
    Utf8,
    Ia5,
    Printable,
    Numeric,
    Visible,
    Bmp,
    Universal,
    General,
    Graphic,
    Teletex,
    T61,
    Videotex,
    Iso646,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct IrEnumItem {
    pub doc: Option<String>,
    pub name: String,
    pub value: Option<i128>,
    pub is_extension: bool,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct IrStruct {
    pub members: Vec<IrStructMember>,
    pub extensible: bool,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum IrStructMember {
    Field(IrField),
    ComponentsOf {
        /// Name of the referenced SEQUENCE/SET type whose components are inlined.
        type_ref: String,
    },
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct IrField {
    pub doc: Option<String>,
    pub name: String,
    pub ty: IrType,
    pub optionality: IrOptionality,
    pub is_extension: bool,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum IrOptionality {
    Required,
    Optional,
    Default(String),
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct IrChoice {
    pub alternatives: Vec<IrField>,
    pub extensible: bool,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum IrConstraint {
    /// Inclusive `[lower, upper]`, either bound may be open (`None` means MIN/MAX).
    Range { lower: Option<i128>, upper: Option<i128>, extensible: bool },
    /// A single permitted value, rendered as a string.
    Single(String),
    /// A SIZE constraint — the inner constraint describes the size range.
    Size(Box<IrConstraint>),
    /// Nested union/intersection or anything not reducible to the above.
    Composite(String),
}

// ---------------------------------------------------------------------------
// Lowering
// ---------------------------------------------------------------------------

/// Lower a slice of parsed CST modules into an [`IrProgram`].
///
/// Cross-module references are recorded; unresolvable references are preserved as
/// [`IrType::Reference`] with `module` unset so consumers can decide how to render
/// them.
pub fn lower(modules: &[cst::Module]) -> IrProgram {
    let mut resolver = Resolver::new(modules);
    let ir_modules = modules.iter().map(|m| lower_module(m, &mut resolver)).collect();
    IrProgram { modules: ir_modules }
}

fn lower_module<'a>(m: &'a cst::Module, resolver: &mut Resolver<'a>) -> IrModule {
    resolver.set_current(&m.name.value, &m.imports);
    let items = m.assignments.iter().map(|a| lower_item(a, resolver)).collect();
    IrModule {
        name: m.name.value.clone(),
        oid: m.oid.as_ref().map(|oid| {
            oid.iter()
                .map(|c| IrOidPart {
                    name: c.name.as_ref().map(|n| n.value.clone()),
                    value: c.value,
                })
                .collect()
        }),
        imports: m
            .imports
            .iter()
            .map(|i| IrImport {
                symbols: i.symbols.iter().map(|s| s.value.clone()).collect(),
                from_module: resolver
                    .canonical_module(i.from_module.value.as_str(), i.from_oid.as_deref())
                    .to_string(),
            })
            .collect(),
        items,
    }
}

fn lower_item(a: &cst::Assignment, resolver: &Resolver<'_>) -> IrItem {
    match &a.kind {
        cst::AssignmentKind::Type(t) => IrItem::Type(IrTypeDef {
            name: a.name.value.clone(),
            doc: a.doc.clone(),
            ty: lower_type(t, resolver),
        }),
        cst::AssignmentKind::Value { ty, value } => IrItem::Value(IrValueDef {
            name: a.name.value.clone(),
            doc: a.doc.clone(),
            ty: lower_type(ty, resolver),
            value: render_value(value),
        }),
        cst::AssignmentKind::ObjectClass(class) => IrItem::ObjectClass(IrObjectClassDef {
            name: a.name.value.clone(),
            doc: a.doc.clone(),
            fields: class.fields.iter().map(|f| lower_class_field(f, resolver)).collect(),
        }),
        cst::AssignmentKind::ObjectSet { class_name, set } => IrItem::ObjectSet(IrObjectSetDef {
            name: a.name.value.clone(),
            class_name: class_name.value.clone(),
            extensible: set.extensible,
            members: set.elements.len(),
        }),
        cst::AssignmentKind::Object { class_name, object } => IrItem::Object(IrObjectDef {
            name: a.name.value.clone(),
            class_name: class_name.value.clone(),
            fields: object.fields.iter().map(|f| lower_object_field(f, resolver)).collect(),
        }),
    }
}

fn lower_class_field(f: &cst::FieldSpec, resolver: &Resolver<'_>) -> IrClassField {
    match f {
        cst::FieldSpec::TypeField { name, optional, .. } => {
            IrClassField::Type { name: name.value.clone(), optional: *optional }
        }
        cst::FieldSpec::ValueField { name, ty, unique, optional, .. } => IrClassField::Value {
            name: name.value.clone(),
            ty: lower_type(ty, resolver),
            optional: *optional,
            unique: *unique,
        },
        cst::FieldSpec::VariableTypeValueField { name, field_path, optional, .. } => {
            IrClassField::VariableType {
                name: name.value.clone(),
                field_path: field_path
                    .iter()
                    .map(|r| match r {
                        cst::FieldRef::Type(n) | cst::FieldRef::Value(n) => n.value.clone(),
                    })
                    .collect(),
                optional: *optional,
            }
        }
    }
}

fn lower_object_field(
    f: &cst::ObjectFieldSetting,
    resolver: &Resolver<'_>,
) -> IrObjectFieldBinding {
    match f {
        cst::ObjectFieldSetting::Type { name, ty } => IrObjectFieldBinding {
            name: name.value.clone(),
            binding: IrObjectFieldValue::Type(lower_type(ty, resolver)),
        },
        cst::ObjectFieldSetting::Value { name, value } => IrObjectFieldBinding {
            name: name.value.clone(),
            binding: IrObjectFieldValue::Value(render_value(value)),
        },
    }
}

fn lower_type(t: &cst::Type, resolver: &Resolver<'_>) -> IrType {
    let leading = lower_constraints(&t.constraints);
    match &t.kind {
        cst::TypeKind::Boolean => IrType::Boolean,
        cst::TypeKind::Integer { named_numbers } => IrType::Integer {
            named_numbers: named_numbers
                .iter()
                .filter_map(|nn| match &nn.value {
                    cst::NamedNumberValue::Literal(v) => Some((nn.name.value.clone(), *v)),
                    cst::NamedNumberValue::Reference(_) => None,
                })
                .collect(),
            constraints: leading,
        },
        cst::TypeKind::Real => IrType::Real,
        cst::TypeKind::Null => IrType::Null,
        cst::TypeKind::BitString { named_bits } => IrType::BitString {
            named_bits: named_bits
                .iter()
                .filter_map(|nn| match &nn.value {
                    cst::NamedNumberValue::Literal(v) => Some((nn.name.value.clone(), *v)),
                    cst::NamedNumberValue::Reference(_) => None,
                })
                .collect(),
            constraints: leading,
        },
        cst::TypeKind::OctetString => IrType::OctetString { constraints: leading },
        cst::TypeKind::ObjectIdentifier => IrType::ObjectIdentifier,
        cst::TypeKind::RelativeOid => IrType::RelativeOid,
        cst::TypeKind::CharString(k) => {
            IrType::CharString { kind: lower_char_kind(*k), constraints: leading }
        }
        cst::TypeKind::UtcTime => IrType::UtcTime,
        cst::TypeKind::GeneralizedTime => IrType::GeneralizedTime,
        cst::TypeKind::Enumerated { items, extensible, extension_items } => IrType::Enumerated {
            items: items
                .iter()
                .map(|i| IrEnumItem {
                    doc: i.doc.clone(),
                    name: i.name.value.clone(),
                    value: i.value,
                    is_extension: false,
                })
                .chain(extension_items.iter().map(|i| IrEnumItem {
                    doc: i.doc.clone(),
                    name: i.name.value.clone(),
                    value: i.value,
                    is_extension: true,
                }))
                .collect(),
            extensible: *extensible,
        },
        cst::TypeKind::Sequence(s) => IrType::Sequence(lower_struct(s, resolver)),
        cst::TypeKind::Set(s) => IrType::Set(lower_struct(s, resolver)),
        cst::TypeKind::SequenceOf(inner) => IrType::SequenceOf {
            element: Box::new(lower_type(inner, resolver)),
            constraints: leading,
        },
        cst::TypeKind::SetOf(inner) => {
            IrType::SetOf { element: Box::new(lower_type(inner, resolver)), constraints: leading }
        }
        cst::TypeKind::Choice(c) => IrType::Choice(lower_choice(c, resolver)),
        cst::TypeKind::Reference(name) => {
            let (module, local) = resolver.resolve(&name.value);
            IrType::Reference { module, name: local }
        }
        cst::TypeKind::ClassField { class, path } => IrType::Open {
            description: format!(
                "{}.{}",
                class.value,
                path.iter()
                    .map(|r| match r {
                        cst::FieldRef::Type(n) => format!("&{}", n.value),
                        cst::FieldRef::Value(n) => format!("&{}", n.value),
                    })
                    .collect::<Vec<_>>()
                    .join(".")
            ),
        },
        cst::TypeKind::Any => IrType::Any,
    }
}

fn lower_char_kind(k: cst::CharStringKind) -> IrCharKind {
    match k {
        cst::CharStringKind::Utf8 => IrCharKind::Utf8,
        cst::CharStringKind::Ia5 => IrCharKind::Ia5,
        cst::CharStringKind::Printable => IrCharKind::Printable,
        cst::CharStringKind::Numeric => IrCharKind::Numeric,
        cst::CharStringKind::Visible => IrCharKind::Visible,
        cst::CharStringKind::Bmp => IrCharKind::Bmp,
        cst::CharStringKind::Universal => IrCharKind::Universal,
        cst::CharStringKind::General => IrCharKind::General,
        cst::CharStringKind::Graphic => IrCharKind::Graphic,
        cst::CharStringKind::Teletex => IrCharKind::Teletex,
        cst::CharStringKind::T61 => IrCharKind::T61,
        cst::CharStringKind::Videotex => IrCharKind::Videotex,
        cst::CharStringKind::Iso646 => IrCharKind::Iso646,
    }
}

fn lower_struct(s: &cst::StructType, resolver: &Resolver<'_>) -> IrStruct {
    let mut members = Vec::new();
    for m in &s.components {
        members.push(lower_struct_member(m, resolver, false));
    }
    for m in &s.extension_additions {
        members.push(lower_struct_member(m, resolver, true));
    }
    IrStruct { members, extensible: s.extensible }
}

fn lower_struct_member(
    m: &cst::StructMember,
    resolver: &Resolver<'_>,
    is_extension: bool,
) -> IrStructMember {
    match m {
        cst::StructMember::Named(c) => {
            IrStructMember::Field(lower_field(c, resolver, is_extension))
        }
        cst::StructMember::ComponentsOf { ty, .. } => {
            let name = match &ty.kind {
                cst::TypeKind::Reference(n) => n.value.clone(),
                _ => "<inline>".to_string(),
            };
            IrStructMember::ComponentsOf { type_ref: name }
        }
    }
}

fn lower_field(c: &cst::Component, resolver: &Resolver<'_>, is_extension: bool) -> IrField {
    IrField {
        doc: c.doc.clone(),
        name: c.name.value.clone(),
        ty: lower_type(&c.ty, resolver),
        optionality: match &c.optionality {
            cst::Optionality::Required => IrOptionality::Required,
            cst::Optionality::Optional => IrOptionality::Optional,
            cst::Optionality::Default(v) => IrOptionality::Default(render_value(v)),
        },
        is_extension,
    }
}

fn lower_choice(c: &cst::ChoiceType, resolver: &Resolver<'_>) -> IrChoice {
    let mut alternatives = Vec::new();
    for a in &c.alternatives {
        alternatives.push(lower_field(a, resolver, false));
    }
    for a in &c.extension_alternatives {
        alternatives.push(lower_field(a, resolver, true));
    }
    IrChoice { alternatives, extensible: c.extensible }
}

fn lower_constraints(cs: &[cst::Constraint]) -> Vec<IrConstraint> {
    cs.iter().map(lower_constraint).collect()
}

fn lower_constraint(c: &cst::Constraint) -> IrConstraint {
    match c {
        cst::Constraint::Size(inner) => IrConstraint::Size(Box::new(lower_constraint(inner))),
        cst::Constraint::ValueRange { lower, upper, extensible } => IrConstraint::Range {
            lower: bound_to_int(lower),
            upper: bound_to_int(upper),
            extensible: *extensible,
        },
        cst::Constraint::SingleValue(v) => IrConstraint::Single(render_value(v)),
        cst::Constraint::Union(list) | cst::Constraint::Intersection(list) => {
            IrConstraint::Composite(
                list.iter().map(render_constraint_brief).collect::<Vec<_>>().join(" / "),
            )
        }
        cst::Constraint::WithComponents(_) => IrConstraint::Composite("WITH COMPONENTS".into()),
        cst::Constraint::Pattern(p) => IrConstraint::Composite(format!("PATTERN {p}")),
        cst::Constraint::ContainedSubtype(_) => IrConstraint::Composite("CONTAINING".into()),
        cst::Constraint::ObjectSet(n) => IrConstraint::Composite(format!("{{{{{}}}}}", n.value)),
        cst::Constraint::Extensible(inner) => {
            let lowered = lower_constraint(inner);
            match lowered {
                IrConstraint::Range { lower, upper, .. } => {
                    IrConstraint::Range { lower, upper, extensible: true }
                }
                other => IrConstraint::Composite(format!("{}, ...", render_ir_constraint(&other))),
            }
        }
        cst::Constraint::Opaque => IrConstraint::Composite("…".into()),
    }
}

fn bound_to_int(b: &cst::ValueBound) -> Option<i128> {
    match b {
        cst::ValueBound::Min | cst::ValueBound::Max => None,
        cst::ValueBound::Value(v) => match v {
            cst::Value::Integer(n) => Some(*n),
            _ => None,
        },
    }
}

fn render_constraint_brief(c: &cst::Constraint) -> String {
    match c {
        cst::Constraint::SingleValue(v) => render_value(v),
        cst::Constraint::ValueRange { lower, upper, .. } => {
            format!("{}..{}", render_bound(lower), render_bound(upper))
        }
        cst::Constraint::Size(_) => "SIZE(..)".into(),
        _ => "..".into(),
    }
}

fn render_bound(b: &cst::ValueBound) -> String {
    match b {
        cst::ValueBound::Min => "MIN".into(),
        cst::ValueBound::Max => "MAX".into(),
        cst::ValueBound::Value(v) => render_value(v),
    }
}

fn render_ir_constraint(c: &IrConstraint) -> String {
    match c {
        IrConstraint::Range { lower, upper, .. } => format!(
            "{}..{}",
            lower.map(|n| n.to_string()).unwrap_or_else(|| "MIN".into()),
            upper.map(|n| n.to_string()).unwrap_or_else(|| "MAX".into()),
        ),
        IrConstraint::Single(s) => s.clone(),
        IrConstraint::Size(inner) => format!("SIZE({})", render_ir_constraint(inner)),
        IrConstraint::Composite(s) => s.clone(),
    }
}

fn render_value(v: &cst::Value) -> String {
    match v {
        cst::Value::Boolean(b) => b.to_string(),
        cst::Value::Null => "NULL".into(),
        cst::Value::Integer(n) => n.to_string(),
        cst::Value::Real(r) => r.to_string(),
        cst::Value::String(s) => format!("\"{s}\""),
        cst::Value::BString(s) => format!("'{s}'B"),
        cst::Value::HString(s) => format!("'{s}'H"),
        cst::Value::NamedNumber(n) | cst::Value::Reference(n) => n.value.clone(),
        cst::Value::Oid(parts) => {
            let s = parts
                .iter()
                .map(|p| match (&p.name, p.value) {
                    (Some(n), Some(v)) => format!("{}({v})", n.value),
                    (Some(n), None) => n.value.clone(),
                    (None, Some(v)) => v.to_string(),
                    (None, None) => "?".into(),
                })
                .collect::<Vec<_>>()
                .join(" ");
            format!("{{ {s} }}")
        }
        cst::Value::Sequence(fields) => {
            let body = fields
                .iter()
                .map(|(n, v)| format!("{} {}", n.value, render_value(v)))
                .collect::<Vec<_>>()
                .join(", ");
            format!("{{ {body} }}")
        }
        cst::Value::SequenceOf(items) => {
            let body = items.iter().map(render_value).collect::<Vec<_>>().join(", ");
            format!("{{ {body} }}")
        }
        cst::Value::Choice(name, inner) => format!("{} : {}", name.value, render_value(inner)),
    }
}

// ---------------------------------------------------------------------------
// Name resolver
// ---------------------------------------------------------------------------

struct Resolver<'a> {
    /// Maps module name -> set of type names defined there.
    module_types: HashMap<&'a str, Vec<&'a str>>,
    /// Maps module name -> its `IMPORTS` clauses, used to follow re-export chains.
    module_imports: HashMap<&'a str, &'a [cst::ImportClause]>,
    /// Module OIDs as arc vectors, used for exact and successor matching.
    module_oids: Vec<(Vec<i64>, &'a str)>,
    current_module: &'a str,
    /// Maps imported symbol name to its origin module.
    imports: HashMap<&'a str, &'a str>,
}

impl<'a> Resolver<'a> {
    fn new(modules: &'a [cst::Module]) -> Self {
        let mut module_types: HashMap<&'a str, Vec<&'a str>> = HashMap::new();
        let mut module_imports: HashMap<&'a str, &'a [cst::ImportClause]> = HashMap::new();
        let mut module_oids: Vec<(Vec<i64>, &'a str)> = Vec::new();
        for m in modules {
            let names: Vec<&str> = m
                .assignments
                .iter()
                .filter(|a| matches!(a.kind, cst::AssignmentKind::Type(_)))
                .map(|a| a.name.value.as_str())
                .collect();
            module_types.insert(m.name.value.as_str(), names);
            module_imports.insert(m.name.value.as_str(), m.imports.as_slice());
            if let Some(arcs) = m.oid.as_deref().and_then(numeric_oid) {
                module_oids.push((arcs, m.name.value.as_str()));
            }
        }
        Self {
            module_types,
            module_imports,
            module_oids,
            current_module: "",
            imports: HashMap::new(),
        }
    }

    /// Map the name used in an `IMPORTS ... FROM` clause onto a module that is
    /// actually present in the program.
    ///
    /// Specifications in the wild sometimes cite a module under a different name
    /// than the one in its header (`CITSapplMgmtApplReg` vs
    /// `CITSapplMgmtApplReg2`) while quoting the very same object identifier, so
    /// the OID is the more reliable key when the name misses. Failing that, a
    /// module whose OID differs only in its trailing version arcs is accepted as
    /// a successor (`ITS-Container {… 102894 cdd(2) version(2)}` is superseded by
    /// `ETSI-ITS-CDD {… 102894 cdd(2) major-version-4(4) minor-version-3(3)}`).
    fn canonical_module(&self, name: &'a str, oid: Option<&[cst::OidComponent]>) -> &'a str {
        if self.module_types.contains_key(name) {
            return name;
        }
        let Some(want) = oid.and_then(numeric_oid) else { return name };
        if let Some((_, exact)) = self.module_oids.iter().find(|(arcs, _)| *arcs == want) {
            return exact;
        }
        // Require everything but the version arcs to agree, so unrelated modules
        // that merely share an issuing-body prefix are never conflated.
        let min_shared = want.len().saturating_sub(2).max(3);
        let mut best: Option<(usize, &'a str)> = None;
        let mut ambiguous = false;
        for (arcs, module) in &self.module_oids {
            let shared = arcs.iter().zip(&want).take_while(|(a, b)| a == b).count();
            if shared < min_shared {
                continue;
            }
            match best {
                Some((len, _)) if len > shared => {}
                Some((len, m)) if len == shared && m != *module => ambiguous = true,
                _ => {
                    best = Some((shared, module));
                    ambiguous = false;
                }
            }
        }
        match best {
            Some((_, module)) if !ambiguous => module,
            _ => name,
        }
    }

    fn set_current(&mut self, name: &'a str, imports: &'a [cst::ImportClause]) {
        self.current_module = name;
        self.imports.clear();
        for imp in imports {
            let origin =
                self.canonical_module(imp.from_module.value.as_str(), imp.from_oid.as_deref());
            for sym in &imp.symbols {
                self.imports.insert(sym.value.as_str(), origin);
            }
        }
    }

    /// Returns `(module, name)`; `module = None` when the reference could not
    /// be resolved to any known module.
    fn resolve(&self, name: &str) -> (Option<String>, String) {
        if let Some(types) = self.module_types.get(self.current_module) {
            if types.contains(&name) {
                return (Some(self.current_module.to_string()), name.to_string());
            }
        }
        if let Some(origin) = self.imports.get(name) {
            return (Some(self.trace_symbol(origin, name).to_string()), name.to_string());
        }
        (None, name.to_string())
    }

    /// Follow `IMPORTS` chains until the module that actually defines `name` is
    /// found. A module that merely imports a symbol is commonly cited as its
    /// source by downstream modules, so a single hop is not always enough.
    /// Returns the last module reached when the chain dead-ends.
    fn trace_symbol(&self, origin: &'a str, name: &str) -> &'a str {
        let mut current = origin;
        let mut seen = std::collections::HashSet::new();
        while seen.insert(current) {
            match self.module_types.get(current) {
                Some(types) if types.contains(&name) => return current,
                Some(_) => {}
                None => break,
            }
            let Some(imports) = self.module_imports.get(current) else { break };
            let Some(next) =
                imports.iter().find(|imp| imp.symbols.iter().any(|s| s.value == name)).map(|imp| {
                    self.canonical_module(imp.from_module.value.as_str(), imp.from_oid.as_deref())
                })
            else {
                break;
            };
            current = next;
        }
        current
    }
}

/// Render an object identifier as its numeric arcs, or `None` when any arc lacks
/// a numeric value (`{iso standard}` style references).
fn numeric_oid(comps: &[cst::OidComponent]) -> Option<Vec<i64>> {
    if comps.is_empty() {
        return None;
    }
    comps.iter().map(|c| c.value).collect()
}

// ---------------------------------------------------------------------------
// Convenience queries
// ---------------------------------------------------------------------------

impl IrProgram {
    /// Find a type definition by module + name.
    pub fn find_type(&self, module: &str, name: &str) -> Option<&IrTypeDef> {
        self.modules.iter().find(|m| m.name == module)?.items.iter().find_map(|i| match i {
            IrItem::Type(t) if t.name == name => Some(t),
            _ => None,
        })
    }

    /// Iterate every type definition across modules.
    pub fn all_types(&self) -> impl Iterator<Item = (&IrModule, &IrTypeDef)> {
        self.modules.iter().flat_map(|m| {
            m.items.iter().filter_map(move |i| match i {
                IrItem::Type(t) => Some((m, t)),
                _ => None,
            })
        })
    }

    /// Collect resolution diagnostics: unresolved type references and imports
    /// whose source module is not present in the program.
    pub fn diagnostics(&self) -> Vec<IrDiagnostic> {
        let mut out = Vec::new();
        let known_modules: std::collections::HashSet<&str> =
            self.modules.iter().map(|m| m.name.as_str()).collect();

        for m in &self.modules {
            for imp in &m.imports {
                if !known_modules.contains(imp.from_module.as_str()) {
                    out.push(IrDiagnostic::UnknownImportedModule {
                        module: m.name.clone(),
                        from_module: imp.from_module.clone(),
                        symbols: imp.symbols.clone(),
                    });
                }
            }
            for item in &m.items {
                if let IrItem::Type(td) = item {
                    collect_unresolved_in_type(
                        &td.ty,
                        &m.name,
                        &td.name,
                        &known_modules,
                        self,
                        &mut out,
                    );
                }
            }
        }
        out
    }
}

/// A resolution-time warning emitted by [`IrProgram::diagnostics`].
#[derive(Debug, Clone)]
pub enum IrDiagnostic {
    /// A type reference could not be resolved to any known module.
    UnresolvedTypeReference { module: String, item: String, referenced: String },
    /// A reference names a module, but that module does not define the symbol.
    UnknownTypeInModule {
        module: String,
        item: String,
        referenced_module: String,
        referenced: String,
    },
    /// An `IMPORTS ... FROM <module>` clause names a module not present in the program.
    UnknownImportedModule { module: String, from_module: String, symbols: Vec<String> },
}

impl std::fmt::Display for IrDiagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IrDiagnostic::UnresolvedTypeReference { module, item, referenced } => write!(
                f,
                "unresolved type reference `{referenced}` in {module}.{item} \
                 (not defined locally and not imported)"
            ),
            IrDiagnostic::UnknownTypeInModule { module, item, referenced_module, referenced } => {
                write!(
                    f,
                    "reference `{referenced_module}.{referenced}` in {module}.{item} — \
                 module `{referenced_module}` has no such type"
                )
            }
            IrDiagnostic::UnknownImportedModule { module, from_module, symbols } => {
                write!(
                    f,
                    "module `{module}` imports {:?} from unknown module `{from_module}`",
                    symbols
                )
            }
        }
    }
}

fn collect_unresolved_in_type(
    ty: &IrType,
    module: &str,
    item: &str,
    known_modules: &std::collections::HashSet<&str>,
    program: &IrProgram,
    out: &mut Vec<IrDiagnostic>,
) {
    match ty {
        IrType::Reference { module: Some(m), name }
            if !known_modules.contains(m.as_str()) || program.find_type(m, name).is_none() =>
        {
            out.push(IrDiagnostic::UnknownTypeInModule {
                module: module.to_string(),
                item: item.to_string(),
                referenced_module: m.clone(),
                referenced: name.clone(),
            });
        }
        IrType::Reference { module: None, name } => {
            out.push(IrDiagnostic::UnresolvedTypeReference {
                module: module.to_string(),
                item: item.to_string(),
                referenced: name.clone(),
            });
        }
        IrType::Sequence(s) | IrType::Set(s) => {
            for mem in &s.members {
                if let IrStructMember::Field(f) = mem {
                    collect_unresolved_in_type(&f.ty, module, item, known_modules, program, out);
                }
            }
        }
        IrType::SequenceOf { element, .. } | IrType::SetOf { element, .. } => {
            collect_unresolved_in_type(element, module, item, known_modules, program, out);
        }
        IrType::Choice(c) => {
            for alt in &c.alternatives {
                collect_unresolved_in_type(&alt.ty, module, item, known_modules, program, out);
            }
        }
        _ => {}
    }
}

/// Pretty-render an [`IrType`] into a short human string (used by viz and tests).
pub fn render_type(ty: &IrType) -> String {
    match ty {
        IrType::Boolean => "BOOLEAN".into(),
        IrType::Integer { .. } => "INTEGER".into(),
        IrType::Real => "REAL".into(),
        IrType::Null => "NULL".into(),
        IrType::BitString { .. } => "BIT STRING".into(),
        IrType::OctetString { .. } => "OCTET STRING".into(),
        IrType::ObjectIdentifier => "OBJECT IDENTIFIER".into(),
        IrType::RelativeOid => "RELATIVE-OID".into(),
        IrType::CharString { kind, .. } => format!("{kind:?}String").replace("Ia5", "IA5"),
        IrType::UtcTime => "UTCTime".into(),
        IrType::GeneralizedTime => "GeneralizedTime".into(),
        IrType::Enumerated { .. } => "ENUMERATED".into(),
        IrType::Sequence(_) => "SEQUENCE".into(),
        IrType::Set(_) => "SET".into(),
        IrType::SequenceOf { element, .. } => format!("SEQUENCE OF {}", render_type(element)),
        IrType::SetOf { element, .. } => format!("SET OF {}", render_type(element)),
        IrType::Choice(_) => "CHOICE".into(),
        IrType::Reference { module, name } => match module {
            Some(m) => format!("{m}.{name}"),
            None => name.clone(),
        },
        IrType::Open { description } => format!("OPEN({description})"),
        IrType::Any => "ANY".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asn1_parser::{parse_source, SourceMap};

    fn parse(src: &str) -> cst::Module {
        let mut sm = SourceMap::new();
        let f = sm.add("t.asn", src.to_string());
        parse_source(&sm, f).unwrap()
    }

    #[test]
    fn lowers_simple_sequence() {
        let m = parse(
            r#"Foo DEFINITIONS AUTOMATIC TAGS ::= BEGIN
                Point ::= SEQUENCE { x INTEGER, y INTEGER OPTIONAL }
            END"#,
        );
        let ir = lower(&[m]);
        let point = ir.find_type("Foo", "Point").unwrap();
        let IrType::Sequence(s) = &point.ty else {
            panic!("expected sequence");
        };
        assert_eq!(s.members.len(), 2);
        match &s.members[1] {
            IrStructMember::Field(f) => assert!(matches!(f.optionality, IrOptionality::Optional)),
            _ => panic!("field"),
        }
    }

    #[test]
    fn resolves_intra_module_references() {
        let m = parse(
            r#"Foo DEFINITIONS AUTOMATIC TAGS ::= BEGIN
                Id ::= INTEGER
                Wrapper ::= SEQUENCE { id Id }
            END"#,
        );
        let ir = lower(&[m]);
        let w = ir.find_type("Foo", "Wrapper").unwrap();
        let IrType::Sequence(s) = &w.ty else { panic!() };
        let IrStructMember::Field(f) = &s.members[0] else { panic!() };
        match &f.ty {
            IrType::Reference { module, name } => {
                assert_eq!(module.as_deref(), Some("Foo"));
                assert_eq!(name, "Id");
            }
            _ => panic!("expected reference"),
        }
    }

    #[test]
    fn import_resolves_by_oid_when_module_name_differs() {
        let a = parse(
            r#"RegistryV2 {iso(1) standard(0) reg(17419) applRegistry(2) version2(2)}
            DEFINITIONS AUTOMATIC TAGS ::= BEGIN
                ItsAid ::= INTEGER
            END"#,
        );
        let b = parse(
            r#"Client DEFINITIONS AUTOMATIC TAGS ::= BEGIN
                IMPORTS ItsAid FROM Registry {iso(1) standard(0) reg(17419) applRegistry(2) version2(2)} ;
                Info ::= SEQUENCE { aid ItsAid }
            END"#,
        );
        let ir = lower(&[a, b]);
        assert!(ir.diagnostics().is_empty(), "{:?}", ir.diagnostics());
        let info = ir.find_type("Client", "Info").unwrap();
        let IrType::Sequence(s) = &info.ty else { panic!() };
        let IrStructMember::Field(f) = &s.members[0] else { panic!() };
        let IrType::Reference { module, .. } = &f.ty else { panic!() };
        assert_eq!(module.as_deref(), Some("RegistryV2"));
    }

    #[test]
    fn import_resolves_to_successor_module_version() {
        let a = parse(
            r#"Cdd {itu-t(0) etsi(0) ts(102894) cdd(2) major-version-4(4) minor-version-3(3)}
            DEFINITIONS AUTOMATIC TAGS ::= BEGIN
                Latitude ::= INTEGER
            END"#,
        );
        let b = parse(
            r#"Client DEFINITIONS AUTOMATIC TAGS ::= BEGIN
                IMPORTS Latitude FROM ITS-Container {itu-t(0) etsi(0) ts(102894) cdd(2) version(2)} ;
                Pos ::= SEQUENCE { lat Latitude }
            END"#,
        );
        let ir = lower(&[a, b]);
        assert!(ir.diagnostics().is_empty(), "{:?}", ir.diagnostics());
        let pos = ir.find_type("Client", "Pos").unwrap();
        let IrType::Sequence(s) = &pos.ty else { panic!() };
        let IrStructMember::Field(f) = &s.members[0] else { panic!() };
        let IrType::Reference { module, .. } = &f.ty else { panic!() };
        assert_eq!(module.as_deref(), Some("Cdd"));
    }

    #[test]
    fn unrelated_oid_is_not_treated_as_successor() {
        let a = parse(
            r#"Cdd {itu-t(0) etsi(0) ts(102894) cdd(2) major-version-4(4)}
            DEFINITIONS AUTOMATIC TAGS ::= BEGIN
                Latitude ::= INTEGER
            END"#,
        );
        let b = parse(
            r#"Client DEFINITIONS AUTOMATIC TAGS ::= BEGIN
                IMPORTS Area FROM Temp-Imports {itu-t(0) etsi(0) ts(103300) temp(255) version1(1)} ;
                Shape ::= SEQUENCE { area Area }
            END"#,
        );
        let ir = lower(&[a, b]);
        let shape = ir.find_type("Client", "Shape").unwrap();
        let IrType::Sequence(s) = &shape.ty else { panic!() };
        let IrStructMember::Field(f) = &s.members[0] else { panic!() };
        let IrType::Reference { module, .. } = &f.ty else { panic!() };
        assert_eq!(module.as_deref(), Some("Temp-Imports"));
    }

    #[test]
    fn reference_follows_reexport_chain_to_defining_module() {
        let cdd = parse(
            r#"Cdd DEFINITIONS AUTOMATIC TAGS ::= BEGIN
                GenerationDeltaTime ::= INTEGER
            END"#,
        );
        let cam = parse(
            r#"Cam DEFINITIONS AUTOMATIC TAGS ::= BEGIN
                IMPORTS GenerationDeltaTime FROM Cdd ;
                Cam ::= SEQUENCE { t GenerationDeltaTime }
            END"#,
        );
        let imzm = parse(
            r#"Imzm DEFINITIONS AUTOMATIC TAGS ::= BEGIN
                IMPORTS GenerationDeltaTime FROM Cam ;
                Msg ::= SEQUENCE { t GenerationDeltaTime }
            END"#,
        );
        let ir = lower(&[cdd, cam, imzm]);
        assert!(ir.diagnostics().is_empty(), "{:?}", ir.diagnostics());
        let msg = ir.find_type("Imzm", "Msg").unwrap();
        let IrType::Sequence(s) = &msg.ty else { panic!() };
        let IrStructMember::Field(f) = &s.members[0] else { panic!() };
        let IrType::Reference { module, .. } = &f.ty else { panic!() };
        assert_eq!(module.as_deref(), Some("Cdd"));
    }

    #[test]
    fn enumerated_lowered_with_extensions() {
        let m = parse(
            r#"Foo DEFINITIONS AUTOMATIC TAGS ::= BEGIN
                Color ::= ENUMERATED { red, green (1), blue, ..., yellow (99) }
            END"#,
        );
        let ir = lower(&[m]);
        let IrType::Enumerated { items, extensible } = &ir.find_type("Foo", "Color").unwrap().ty
        else {
            panic!();
        };
        assert!(*extensible);
        assert_eq!(items.len(), 4);
        assert!(items.iter().any(|i| i.name == "yellow" && i.is_extension));
    }
}
