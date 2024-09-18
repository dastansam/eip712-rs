//! Resolves the structs in the solidity file.

use proc_macro2::Span;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::{Debug, Display},
    num::NonZero,
};
use syn::{
    punctuated::Punctuated,
    token::{Brace, Bracket, Dot, Paren, Plus, Semi},
    Token,
};
use syn_solidity::{
    kw, ArgList, BinOp, Block, Expr, ExprBinary, ExprCall, ExprIndex, ExprMember, ExprNew,
    ExprPostfix, ExprUnary, ForInitStmt, FunctionAttribute, FunctionAttributes, FunctionKind,
    ItemFunction, Lit, LitStr, Mutability, Parameters, PostUnOp, Returns, SolIdent, SolPath, Stmt,
    StmtExpr, StmtFor, StmtReturn, StmtVarDecl, Storage, Type, TypeArray, UnOp, VariableAttribute,
    VariableAttributes, VariableDeclaration, VariableDefinition,
};

use crate::{
    types::{BytesU32, ItemFunctionWrapper, VariableDefinitionWrapper},
    utils::{self, camel_to_uppercase, struct_to_param_name},
};

/// Field of a struct.
#[derive(Debug, Clone)]
pub(crate) struct FieldItem {
    /// The name of the field.
    pub(crate) name: String,
    /// The type of the field.
    pub(crate) type_: Type,
}

impl Display for FieldItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.type_, self.name)
    }
}

/// A more structured and convenient representation of a Solidity struct.
#[derive(Debug, Clone)]
pub(crate) struct StructItem {
    /// The name of the struct.
    pub(crate) name: String,
    /// The fields of the struct.
    /// Order is important.
    pub(crate) fields: Vec<FieldItem>,
    /// The index of the struct in the original Solidity file.
    pub(crate) index: usize,
    /// Generate array type hash function for the struct.
    /// Determined by checking if the struct is used as an array parameter in any function.
    pub(crate) has_array_type_hash_function: bool,
}

impl Display for StructItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut result = format!("{}(", self.name);

        for (i, field) in self.fields.iter().enumerate() {
            result.push_str(&format!("{}", field));
            if self.fields.len() - 1 > i {
                result.push_str(",");
            }
        }
        result.push(')');

        write!(f, "{}", result)
    }
}

impl StructItem {
    /// Returns the notation name for the struct.
    fn notation(&self) -> String {
        format!("{}_NOTATION", camel_to_uppercase(&self.name))
    }

    /// Returns the typehash name for the struct.
    fn typehash(&self) -> String {
        format!("{}_TYPEHASH", camel_to_uppercase(&self.name))
    }

    /// Generates the type hash notation and the type hash constant.
    ///
    /// Example:
    ///
    /// ```sol
    /// string constant POLICY_DATA_NOTATION = "PolicyData(address policy,bytes initData)";
    /// bytes32 constant POLICY_DATA_TYPEHASH = keccak256(bytes(POLICY_DATA_NOTATION));
    /// ```
    ///
    /// NOTE: camel case should be converted to uppercase, using the `_` as separator.
    fn generate_constants(&self) -> (VariableDefinitionWrapper, VariableDefinitionWrapper) {
        let notation_name = self.notation();
        let notation_value = Expr::Lit(Lit::Str(LitStr {
            values: vec![syn::LitStr::new(&self.to_string(), Span::call_site())],
        }));

        let typehash_name = self.typehash();
        let typehash_value = Expr::Call(ExprCall {
            expr: Box::new(Expr::Ident(SolIdent::new("keccak256"))),
            args: ArgList {
                paren_token: Paren::default(),
                list: syn_solidity::ArgListImpl::Unnamed(Punctuated::from_iter(vec![Expr::Call(
                    ExprCall {
                        expr: Box::new(Expr::Ident(SolIdent::new("bytes"))),
                        args: ArgList {
                            paren_token: Paren::default(),
                            list: syn_solidity::ArgListImpl::Unnamed(Punctuated::from_iter(vec![
                                Expr::Ident(SolIdent::new(&notation_name)),
                            ])),
                        },
                    },
                )])),
            },
        });

        (
            VariableDefinitionWrapper(VariableDefinition {
                attrs: Vec::new(),
                ty: Type::String(Span::call_site()),
                attributes: VariableAttributes(vec![VariableAttribute::Constant(kw::constant(
                    Span::call_site(),
                ))]),
                name: SolIdent::new(&notation_name),
                initializer: Some((Token![=](Span::call_site()), notation_value)),
                semi_token: Semi { spans: [Span::call_site()] },
            }),
            VariableDefinitionWrapper(VariableDefinition {
                attrs: Vec::new(),
                ty: Type::FixedBytes(Span::call_site(), BytesU32::new(32).expect("32 is non-zero")),
                attributes: VariableAttributes(vec![VariableAttribute::Constant(kw::constant(
                    Span::call_site(),
                ))]),
                name: SolIdent::new(&typehash_name),
                initializer: Some((Token![=](Span::call_site()), typehash_value)),
                semi_token: Semi { spans: [Span::call_site()] },
            }),
        )
    }

    /// Generates the type hash function for a struct.
    ///
    /// Example:
    /// ```solidity
    /// function hashActionData(
    ///     ActionData memory actionData
    /// ) internal pure returns (bytes32) {
    ///     return
    ///         keccak256(
    ///             abi.encode(
    ///                 ACTION_DATA_TYPEHASH,
    ///                 actionData.actionTargetSelector,
    ///                 actionData.actionTarget,
    ///                 hashPolicyDataArray(actionData.actionPolicies)
    ///             )
    ///         );
    /// }
    /// ```
    fn generate_type_hash_function(&self) -> ItemFunctionWrapper {
        let name = format!("hash{}", self.name);
        // make the first letter lowercase
        let param_name = utils::struct_to_param_name(&self.name, false);

        // each field of the struct is hashed, if it's an array, we need to use the array hash
        // function
        let mut args = self
            .fields
            .iter()
            .map(|field| {
                if field.type_.is_array() && field.type_.peel_arrays().is_abi_dynamic() {
                    Expr::Call(ExprCall {
                        expr: Box::new(Expr::Ident(SolIdent::new(&format!(
                            "hash{}Array",
                            utils::ensure_first_letter_uppercase(
                                &field.type_.peel_arrays().to_string()
                            )
                            .expect("safe to unwrap")
                        )))),
                        args: ArgList {
                            paren_token: Paren::default(),
                            list: syn_solidity::ArgListImpl::Unnamed(Punctuated::from_iter(vec![
                                Expr::Member(ExprMember {
                                    expr: Box::new(Expr::Ident(SolIdent::new(&param_name))),
                                    dot_token: Dot::default(),
                                    member: Box::new(Expr::Ident(SolIdent::new(&field.name))),
                                }),
                            ])),
                        },
                    })
                } else if field.type_.is_custom() {
                    Expr::Call(ExprCall {
                        expr: Box::new(Expr::Ident(SolIdent::new(&format!(
                            "hash{}",
                            utils::ensure_first_letter_uppercase(&field.type_.to_string())
                                .expect("safe to unwrap")
                        )))),
                        args: ArgList {
                            paren_token: Paren::default(),
                            list: syn_solidity::ArgListImpl::Unnamed(Punctuated::from_iter(vec![
                                Expr::Member(ExprMember {
                                    expr: Box::new(Expr::Ident(SolIdent::new(&param_name))),
                                    dot_token: Dot::default(),
                                    member: Box::new(Expr::Ident(SolIdent::new(&field.name))),
                                }),
                            ])),
                        },
                    })
                } else {
                    Expr::Member(ExprMember {
                        expr: Box::new(Expr::Ident(SolIdent::new(&param_name))),
                        dot_token: Dot::default(),
                        member: Box::new(Expr::Ident(SolIdent::new(&field.name))),
                    })
                }
            })
            .collect::<Vec<_>>();

        args.insert(0, Expr::Ident(SolIdent::new(self.typehash().as_str())));

        let hash_body = Block {
            brace_token: Brace::default(),
            stmts: vec![Stmt::Return(StmtReturn {
                return_token: Token![return](Span::call_site()),
                expr: Some(Expr::Call(ExprCall {
                    expr: Box::new(Expr::Ident(SolIdent::new("keccak256"))),
                    args: ArgList {
                        paren_token: Paren::default(),
                        list: syn_solidity::ArgListImpl::Unnamed(Punctuated::from_iter(vec![
                            Expr::Call(ExprCall {
                                expr: Box::new(Expr::Member(ExprMember {
                                    expr: Box::new(Expr::Ident(SolIdent::new("abi"))),
                                    dot_token: Dot::default(),
                                    member: Box::new(Expr::Ident(SolIdent::new("encode"))),
                                })),
                                args: ArgList {
                                    paren_token: Paren::default(),
                                    list: syn_solidity::ArgListImpl::Unnamed(
                                        Punctuated::from_iter(args),
                                    ),
                                },
                            }),
                        ])),
                    },
                })),
                semi_token: Semi { spans: [Span::call_site()] },
            })],
        };

        ItemFunctionWrapper(ItemFunction {
            attrs: Vec::new(),
            kind: FunctionKind::Function(kw::function(Span::call_site())),
            name: Some(SolIdent::new(&name)),
            paren_token: None,
            parameters: Parameters::from_iter(vec![VariableDeclaration {
                attrs: Vec::new(),
                ty: Type::Custom(SolPath::from_iter(vec![SolIdent::new(&self.name)])),
                storage: Some(Storage::Memory(kw::memory(Span::call_site()))),
                name: Some(SolIdent::new(&param_name)),
            }]),
            attributes: FunctionAttributes(vec![
                FunctionAttribute::Visibility(syn_solidity::Visibility::Internal(kw::internal(
                    Span::call_site(),
                ))),
                FunctionAttribute::Mutability(Mutability::Pure(kw::pure(Span::call_site()))),
            ]),
            returns: Some(Returns::new(
                Span::call_site(),
                Parameters::from_iter(vec![VariableDeclaration {
                    attrs: Vec::new(),
                    ty: Type::FixedBytes(
                        Span::call_site(),
                        BytesU32::new(32).expect("32 is non-zero"),
                    ),
                    storage: None,
                    name: None,
                }]),
            )),
            body: syn_solidity::FunctionBody::Block(hash_body),
        })
    }
}

/// Helper struct to parse the structs in the Solidity file
pub(crate) struct StructParser {
    /// All the structs in the file.
    pub(crate) structs: BTreeMap<String, StructItem>,
    /// All the array types in the file, i.e uint256[], address[], etc.
    pub(crate) array_types: BTreeSet<String>,
}

impl StructParser {
    /// Parses the structs from [syn_solidity::File].
    pub(crate) fn init(file: &syn_solidity::File) -> eyre::Result<Self> {
        let mut output = BTreeMap::new();
        let mut array_struct_names = BTreeSet::new();
        let mut array_type_names = BTreeSet::new();

        for (idx, item) in file.items.iter().enumerate() {
            if let syn_solidity::Item::Struct(struct_item) = item {
                let name = struct_item.name.to_string();
                let fields = struct_item
                    .fields
                    .iter()
                    .map(|field| {
                        if let Type::Array(TypeArray { ty, .. }) = field.ty.clone() {
                            if matches!(
                                *ty,
                                Type::Array(_)
                                    | Type::Function(_)
                                    | Type::Mapping(_)
                                    | Type::Tuple(_)
                            ) {
                                // TODO: handle nested arrays
                            } else if let Type::Custom(sol_path) = *ty {
                                array_struct_names.insert(sol_path.to_string());
                            } else {
                                // Only include dynamic native types
                                if let Type::String(_) | Type::Bytes(_) = *ty {
                                    array_type_names.insert(ty.to_string());
                                }
                            }
                        }

                        FieldItem {
                            name: field.name.clone().expect("Always some").to_string(),
                            type_: field.ty.clone(),
                        }
                    })
                    .collect();

                output.insert(
                    name.clone(),
                    StructItem { name, fields, index: idx, has_array_type_hash_function: false },
                );
            }
        }

        for array_struct_name in array_struct_names {
            if let Some(struct_item) = output.get_mut(&array_struct_name) {
                struct_item.has_array_type_hash_function = true;
            }
        }

        Ok(Self { structs: output, array_types: array_type_names })
    }

    pub(crate) fn generate_file(&self, input_file: &str, solidity_version: &str) -> String {
        let mut output = String::new();
        // we need to make sure functions are inside library, otherwise they can't be internal
        output.push_str(&format!("pragma solidity ^{};\n", solidity_version));
        output.push_str(&format!("import \"./{}\";\n", input_file));
        output.push_str(&self.generate_constants());
        output.push_str("library TypeHashes {\n");
        output.push_str("\n");
        output.push_str(&self.generate_type_hash_functions());

        output.push_str("}\n");

        output
    }

    /// Collect constants from all structs.
    fn generate_constants(&self) -> String {
        self.structs
            .values()
            .map(|s| {
                let (notation, typehash) = s.generate_constants();
                format!("{};\n{};", notation, typehash)
            })
            .collect()
    }

    /// Generate type hash functions for all structs.
    ///
    /// If the struct is used as a parameter in an array, we need to generate a separate function
    /// to hash the array.
    ///
    /// Also generate an array hash function for dynamic native types (string, bytes)
    fn generate_type_hash_functions(&self) -> String {
        let mut output = String::new();
        for struct_item in self.structs.values() {
            let func = struct_item.generate_type_hash_function();
            let func_str = format!("{}\n", func);
            output.push_str(&func_str);

            if struct_item.has_array_type_hash_function {
                let array_func = generate_array_type_hash_function(&struct_item.name, false);
                let array_func_str = format!("{}\n", array_func);
                output.push_str(&array_func_str);
            }
        }

        for array_type in self.array_types.iter() {
            let array_func = generate_array_type_hash_function(array_type, true);
            let array_func_str = format!("{}\n", array_func);
            output.push_str(&array_func_str);
        }

        output
    }
}

/// For a given array type, generate the hash function.
///
/// Array type could either be a custom struct or a native type
fn generate_array_type_hash_function(array_type: &str, native_type: bool) -> ItemFunctionWrapper {
    let array_type_name =
        utils::ensure_first_letter_uppercase(array_type).expect("Invalid array type");
    let arr_param_name = utils::struct_to_param_name(&format!("{}Array", array_type), false);

    let hasing_expr = if native_type {
        Expr::Call(ExprCall {
            expr: Box::new(Expr::Ident(SolIdent::new("keccak256"))),
            args: ArgList {
                paren_token: Paren::default(),
                list: syn_solidity::ArgListImpl::Unnamed(Punctuated::from_iter(vec![Expr::Call(
                    ExprCall {
                        expr: Box::new(Expr::Member(ExprMember {
                            expr: Box::new(Expr::Ident(SolIdent::new("abi"))),
                            dot_token: Dot::default(),
                            member: Box::new(Expr::Ident(SolIdent::new("encodePacked"))),
                        })),
                        args: ArgList {
                            paren_token: Paren::default(),
                            list: syn_solidity::ArgListImpl::Unnamed(Punctuated::from_iter(vec![
                                Expr::Index(ExprIndex {
                                    expr: Box::new(Expr::Ident(SolIdent::new(&arr_param_name))),
                                    bracket_token: Bracket::default(),
                                    start: Some(Box::new(Expr::Ident(SolIdent::new("i")))),
                                    colon_token: None,
                                    end: None,
                                }),
                            ])),
                        },
                    },
                )])),
            },
        })
    } else {
        Expr::Call(ExprCall {
            expr: Box::new(Expr::Ident(SolIdent::new(&struct_to_param_name(
                &format!("hash{}", array_type_name),
                false,
            )))),
            args: ArgList {
                paren_token: Paren::default(),
                list: syn_solidity::ArgListImpl::Unnamed(Punctuated::from_iter(vec![Expr::Index(
                    ExprIndex {
                        expr: Box::new(Expr::Ident(SolIdent::new(&struct_to_param_name(
                            &format!("{}Array", array_type_name),
                            false,
                        )))),
                        bracket_token: Bracket::default(),
                        start: Some(Box::new(Expr::Ident(SolIdent::new("i")))),
                        colon_token: None,
                        end: None,
                    },
                )])),
            },
        })
    };

    // inner body of the function.
    let hash_array_body = Block {
        brace_token: Brace::default(),
        stmts: vec![
            Stmt::VarDecl(StmtVarDecl {
                declaration: syn_solidity::VarDeclDecl::VarDecl(VariableDeclaration {
                    attrs: Vec::new(),
                    ty: Type::Uint(
                        Span::call_site(),
                        Some(NonZero::new(256).expect("256 is non-zero")),
                    ),
                    storage: None,
                    name: Some(SolIdent::new("length")),
                }),
                assignment: Some((
                    Token![=](Span::call_site()),
                    Expr::Member(ExprMember {
                        expr: Box::new(Expr::Ident(SolIdent::new(&arr_param_name))),
                        dot_token: Dot::default(),
                        member: Box::new(Expr::Ident(SolIdent::new("length"))),
                    }),
                )),
                semi_token: Semi { spans: [Span::call_site()] },
            }),
            Stmt::VarDecl(StmtVarDecl {
                declaration: syn_solidity::VarDeclDecl::VarDecl(VariableDeclaration {
                    attrs: Vec::new(),
                    ty: Type::Array(TypeArray {
                        ty: Box::new(Type::FixedBytes(
                            Span::call_site(),
                            BytesU32::new(32).expect("32 is non-zero"),
                        )),
                        size: None,
                        bracket_token: Bracket::default(),
                    }),
                    storage: Some(Storage::Memory(kw::memory(Span::call_site()))),
                    name: Some(SolIdent::new("hashes")),
                }),
                assignment: Some((
                    Token![=](Span::call_site()),
                    Expr::Call(ExprCall {
                        expr: Box::new(Expr::New(ExprNew {
                            new_token: kw::new(Span::call_site()),
                            ty: Type::Array(TypeArray {
                                ty: Box::new(Type::FixedBytes(
                                    Span::call_site(),
                                    BytesU32::new(32).expect("32 is non-zero"),
                                )),
                                size: None,
                                bracket_token: Bracket::default(),
                            }),
                        })),
                        args: ArgList {
                            paren_token: Paren::default(),
                            list: syn_solidity::ArgListImpl::Unnamed(Punctuated::from_iter(vec![
                                Expr::Ident(SolIdent::new("length")),
                            ])),
                        },
                    }),
                )),
                semi_token: Semi { spans: [Span::call_site()] },
            }),
            Stmt::For(StmtFor {
                for_token: Token![for](Span::call_site()),
                paren_token: Paren::default(),
                init: ForInitStmt::VarDecl(StmtVarDecl {
                    declaration: syn_solidity::VarDeclDecl::VarDecl(VariableDeclaration {
                        attrs: Vec::new(),
                        ty: Type::Uint(
                            Span::call_site(),
                            Some(NonZero::new(256).expect("256 is non-zero")),
                        ),
                        storage: None,
                        name: Some(SolIdent::new("i")),
                    }),
                    assignment: None,
                    semi_token: Semi { spans: [Span::call_site()] },
                }),
                cond: Some(Box::new(Expr::Binary(ExprBinary {
                    left: Box::new(Expr::Ident(SolIdent::new("i"))),
                    op: BinOp::Lt(Token![<](Span::call_site())),
                    right: Box::new(Expr::Ident(SolIdent::new("length"))),
                }))),
                post: Some(Box::new(Expr::Postfix(ExprPostfix {
                    expr: Box::new(Expr::Ident(SolIdent::new("i"))),
                    op: PostUnOp::Increment(
                        Token![+](Span::call_site()),
                        Token![+](Span::call_site()),
                    ),
                }))),
                body: Box::new(Stmt::Block(Block {
                    brace_token: Brace::default(),
                    stmts: vec![Stmt::Expr(StmtExpr {
                        expr: Expr::Binary(ExprBinary {
                            left: Box::new(Expr::Index(ExprIndex {
                                expr: Box::new(Expr::Ident(SolIdent::new("hashes"))),
                                bracket_token: Bracket::default(),
                                start: Some(Box::new(Expr::Ident(SolIdent::new("i")))),
                                colon_token: None,
                                end: None,
                            })),
                            op: BinOp::Assign(Token![=](Span::call_site())),
                            right: Box::new(hasing_expr),
                        }),
                        semi_token: Semi { spans: [Span::call_site()] },
                    })],
                })),
                semi_token: Semi { spans: [Span::call_site()] },
            }),
            Stmt::Return(StmtReturn {
                return_token: Token![return](Span::call_site()),
                expr: Some(Expr::Call(ExprCall {
                    expr: Box::new(Expr::Ident(SolIdent::new("keccak256"))),
                    args: ArgList {
                        paren_token: Paren::default(),
                        list: syn_solidity::ArgListImpl::Unnamed(Punctuated::from_iter(vec![
                            Expr::Call(ExprCall {
                                expr: Box::new(Expr::Member(ExprMember {
                                    expr: Box::new(Expr::Ident(SolIdent::new("abi"))),
                                    dot_token: Dot::default(),
                                    member: Box::new(Expr::Ident(SolIdent::new("encodePacked"))),
                                })),
                                args: ArgList {
                                    paren_token: Paren::default(),
                                    list: syn_solidity::ArgListImpl::Unnamed(
                                        Punctuated::from_iter(vec![Expr::Ident(SolIdent::new(
                                            "hashes",
                                        ))]),
                                    ),
                                },
                            }),
                        ])),
                    },
                })),
                semi_token: Semi { spans: [Span::call_site()] },
            }),
        ],
    };

    ItemFunctionWrapper(ItemFunction {
        attrs: Vec::new(),
        kind: FunctionKind::Function(kw::function(Span::call_site())),
        name: Some(SolIdent::new(&format!("hash{}Array", array_type_name))),
        paren_token: None,
        parameters: Parameters::from_iter(vec![VariableDeclaration {
            attrs: Vec::new(),
            ty: Type::Array(TypeArray {
                ty: Box::new(Type::Custom(SolPath::from_iter(vec![SolIdent::new(&array_type)]))),
                size: None,
                bracket_token: Bracket::default(),
            }),
            storage: Some(Storage::Memory(kw::memory(Span::call_site()))),
            name: Some(SolIdent::new(&arr_param_name)),
        }]),
        attributes: FunctionAttributes(vec![
            FunctionAttribute::Visibility(syn_solidity::Visibility::Internal(kw::internal(
                Span::call_site(),
            ))),
            FunctionAttribute::Mutability(Mutability::Pure(kw::pure(Span::call_site()))),
        ]),
        returns: Some(Returns::new(
            Span::call_site(),
            Parameters::from_iter(vec![VariableDeclaration {
                attrs: Vec::new(),
                ty: Type::FixedBytes(Span::call_site(), BytesU32::new(32).expect("32 is non-zero")),
                storage: None,
                name: None,
            }]),
        )),
        body: syn_solidity::FunctionBody::Block(hash_array_body),
    })
}
