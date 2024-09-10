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
    ExprUnary, ForInitStmt, FunctionAttribute, FunctionAttributes, FunctionKind, ItemFunction, Lit,
    LitStr, Mutability, Parameters, Returns, SolIdent, SolPath, Stmt, StmtExpr, StmtFor,
    StmtReturn, StmtVarDecl, Storage, Type, TypeArray, UnOp, VariableAttribute, VariableAttributes,
    VariableDeclaration, VariableDefinition,
};

use crate::{
    types::{BytesU32, ItemFunctionWrapper, VariableDefinitionWrapper},
    utils::{self, camel_to_uppercase},
};

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
        let notation_name = format!("{}_NOTATION", camel_to_uppercase(&self.name));
        let notation_value = Expr::Lit(Lit::Str(LitStr {
            values: vec![syn::LitStr::new(&self.to_string(), Span::call_site())],
        }));

        let typehash_name = format!("{}_TYPEHASH", camel_to_uppercase(&self.name));
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

    /// Generates the type hash function. If the struct is used as a an array parameter, we need a
    /// separate function to hash the array.
    ///
    /// Example:
    ///
    /// ```sol
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
    /// function hashActionDataArray(
    ///     ActionData[] memory actionDataArray
    /// ) internal pure returns (bytes32) {
    ///     uint256 length = actionDataArray.length;
    ///     bytes32[] memory hashes = new bytes32[](length);
    ///     for (uint256 i; i < length; i++) {
    ///         hashes[i] = actionDataArray[i].hashActionData();
    ///     }
    ///     return keccak256(abi.encodePacked(hashes));
    /// }
    /// ```
    fn generate_type_hash_functions(&self) -> (ItemFunctionWrapper, Option<ItemFunctionWrapper>) {
        let name = format!("hash{}", self.name);
        // make the first letter lowercase
        let param_name = utils::struct_to_param_name(&self.name, false);

        // each field of the struct is hashed, if it's an array, we need to use the array hash
        // function
        let args = self
            .fields
            .iter()
            .map(|field| {
                if field.type_.is_array() {
                    Expr::Member(ExprMember {
                        expr: Box::new(Expr::Ident(SolIdent::new(&param_name))),
                        dot_token: Dot::default(),
                        member: Box::new(Expr::Member(ExprMember {
                            expr: Box::new(Expr::Ident(SolIdent::new(&field.name))),
                            dot_token: Dot::default(),
                            member: Box::new(Expr::Call(ExprCall {
                                expr: Box::new(Expr::Ident(SolIdent::new(&format!(
                                    "hash{}Array",
                                    field.type_.peel_arrays().to_string()
                                )))),
                                args: ArgList {
                                    paren_token: Paren::default(),
                                    list: syn_solidity::ArgListImpl::Unnamed(Punctuated::new()),
                                },
                            })),
                        })),
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

        let hash_array_func = if self.has_array_type_hash_function {
            let arr_param_name = utils::struct_to_param_name(&self.name, false);

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
                            Expr::Call(ExprCall {
                                expr: Box::new(Expr::Member(ExprMember {
                                    expr: Box::new(Expr::Ident(SolIdent::new(&arr_param_name))),
                                    dot_token: Dot::default(),
                                    member: Box::new(Expr::Ident(SolIdent::new("length"))),
                                })),
                                args: ArgList {
                                    paren_token: Paren::default(),
                                    list: syn_solidity::ArgListImpl::Unnamed(Punctuated::new()),
                                },
                            }),
                        )),
                        semi_token: Semi { spans: [Span::call_site()] },
                    }),
                    // bytes32[] memory hashes = new bytes32[](length);
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
                            Expr::New(ExprNew {
                                new_token: kw::new(Span::call_site()),
                                ty: Type::Array(TypeArray {
                                    ty: Box::new(Type::FixedBytes(
                                        Span::call_site(),
                                        BytesU32::new(32).expect("32 is non-zero"),
                                    )),
                                    size: Some(Box::new(Expr::Ident(SolIdent::new("length")))),
                                    bracket_token: Bracket::default(),
                                }),
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
                        post: Some(Box::new(Expr::Unary(ExprUnary {
                            op: UnOp::Increment(Plus::default(), Plus::default()),
                            expr: Box::new(Expr::Ident(SolIdent::new("i"))),
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
                                    right: Box::new(Expr::Member(ExprMember {
                                        expr: Box::new(Expr::Index(ExprIndex {
                                            expr: Box::new(Expr::Ident(SolIdent::new(
                                                "actionDataArray",
                                            ))),
                                            bracket_token: Bracket::default(),
                                            start: Some(Box::new(Expr::Ident(SolIdent::new("i")))),
                                            colon_token: None,
                                            end: None,
                                        })),
                                        dot_token: Dot::default(),
                                        member: Box::new(Expr::Call(ExprCall {
                                            expr: Box::new(Expr::Ident(SolIdent::new(
                                                "hashActionData",
                                            ))),
                                            args: ArgList {
                                                paren_token: Paren::default(),
                                                list: syn_solidity::ArgListImpl::Unnamed(
                                                    Punctuated::new(),
                                                ),
                                            },
                                        })),
                                    })),
                                }),
                                semi_token: Semi { spans: [Span::call_site()] },
                            })],
                        })),
                        semi_token: Semi { spans: [Span::call_site()] },
                    }),
                ],
            };

            Some(ItemFunctionWrapper(ItemFunction {
                attrs: Vec::new(),
                kind: FunctionKind::Function(kw::function(Span::call_site())),
                name: Some(SolIdent::new(&format!("hash{}Array", self.name))),
                paren_token: None,
                parameters: Parameters::from_iter(vec![VariableDeclaration {
                    attrs: Vec::new(),
                    ty: Type::Custom(SolPath::from_iter(vec![SolIdent::new(&self.name)])),
                    storage: Some(Storage::Memory(kw::memory(Span::call_site()))),
                    name: Some(SolIdent::new(&arr_param_name)),
                }]),
                attributes: FunctionAttributes(vec![
                    FunctionAttribute::Visibility(syn_solidity::Visibility::Internal(
                        kw::internal(Span::call_site()),
                    )),
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
                body: syn_solidity::FunctionBody::Block(hash_array_body),
            }))
        } else {
            None
        };

        (
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
                    FunctionAttribute::Visibility(syn_solidity::Visibility::Internal(
                        kw::internal(Span::call_site()),
                    )),
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
            }),
            hash_array_func,
        )
    }
}

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

/// Parses the structs in the Solidity file.
pub(crate) struct StructParser(pub(crate) BTreeMap<String, StructItem>);

impl StructParser {
    /// Parses the structs from [syn_solidity::File].
    pub(crate) fn init(file: &syn_solidity::File) -> eyre::Result<Self> {
        let mut output = BTreeMap::new();
        let mut array_struct_names = BTreeSet::new();

        for (idx, item) in file.items.iter().enumerate() {
            if let syn_solidity::Item::Struct(struct_item) = item {
                let name = struct_item.name.to_string();
                let fields = struct_item
                    .fields
                    .iter()
                    .map(|field| {
                        if let Type::Array(TypeArray { ty, .. }) = field.ty.clone() {
                            if let Type::Custom(sol_path) = *ty {
                                array_struct_names.insert(sol_path.to_string());
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

        Ok(Self(output))
    }

    pub(crate) fn generate_file(&self, solidity_version: &str) -> String {
        let mut output = String::new();
        // we need to make sure functions are inside library, otherwise they can't be internal
        output.push_str(&format!("pragma solidity ^{};\n", solidity_version));
        output.push_str("library TypeHashes {\n");
        output.push_str(&self.generate_constants());
        output.push_str("\n");
        output.push_str(&self.generate_type_hash_functions());

        output.push_str("}\n");

        output
    }

    /// Collect constants from all structs.
    fn generate_constants(&self) -> String {
        self.0
            .values()
            .map(|s| {
                let (notation, typehash) = s.generate_constants();
                format!("{};\n{};", notation, typehash)
            })
            .collect()
    }

    /// Generate type hash functions for all structs.
    fn generate_type_hash_functions(&self) -> String {
        self.0
            .values()
            .map(|s| {
                let (func, array_func) = s.generate_type_hash_functions();
                let func_str = format!("{}\n", func);
                if let Some(array_func) = array_func {
                    format!("{}\n{}\n", func_str, array_func)
                } else {
                    func_str
                }
            })
            .collect()
    }
}
