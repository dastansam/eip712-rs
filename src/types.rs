//! Types used in the CLI.

use std::fmt::Display;
use syn_solidity::{ArgListImpl, Expr, ItemFunction, Lit, VariableDefinition};

pub(crate) type BytesU32 = std::num::NonZero<u16>;

/// [Display] implementation specifically for handling [Expr]
pub(crate) fn fmt_call(call: &Expr) -> eyre::Result<String> {
    match call {
        Expr::Lit(lit) => match lit {
            Lit::Str(string) => Ok(format!("\"{}\"", string.to_string())),
            _ => Err(eyre::Report::msg("Unsupported literal type")),
        },
        Expr::Ident(ident) => Ok(ident.to_string()),
        Expr::Call(call) => {
            let mut result = String::new();
            let expr_str = fmt_call(&call.expr)?;
            result.push_str(&expr_str);
            result.push('(');
            if let ArgListImpl::Unnamed(args) = &call.args.list {
                for (i, arg) in args.iter().enumerate() {
                    let arg_str = fmt_call(arg)?;
                    result.push_str(&arg_str);
                    if i < args.len() - 1 {
                        result.push(',');
                        result.push(' ');
                    }
                }
            }
            result.push(')');
            Ok(result)
        }
        Expr::Member(member) => {
            let mut result = String::new();
            let expr_str = fmt_call(&member.expr)?;
            result.push_str(&expr_str);

            result.push('.');

            let member_str = fmt_call(&member.member)?;
            result.push_str(&member_str);
            Ok(result)
        }
        _ => Err(eyre::Report::msg("Unsupported expression type")),
    }
}

/// To implement `Display` for `VariableDefinition`.
pub(crate) struct VariableDefinitionWrapper(pub(crate) VariableDefinition);

impl Display for VariableDefinitionWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {} {}", self.0.ty, self.0.attributes, self.0.name)?;
        if let Some((_, expr)) = &self.0.initializer {
            write!(f, " = ")?;
            if let Ok(res) = fmt_call(expr) {
                write!(f, "{}", res)?;
            } else {
                write!(f, " <expr> ")?;
            }
        }
        Ok(())
    }
}

/// To implement `Display` for `ItemFunction`.
pub(crate) struct ItemFunctionWrapper(pub(crate) ItemFunction);

/// This is exact same impl as [ItemFunction]'s, but [FunctionBody] does not implement `Display`,
/// so we need to implement it manually.
impl Display for ItemFunctionWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0.kind.as_str())?;
        if let Some(name) = &self.0.name {
            f.write_str(" ")?;
            name.fmt(f)?;
        }
        write!(f, "({})", self.0.parameters)?;

        if !self.0.attributes.is_empty() {
            write!(f, " {}", self.0.attributes)?;
        }

        if let Some(returns) = &self.0.returns {
            write!(f, " {returns}")?;
        }

        if !self.0.body.is_empty() {
            f.write_str(" ")?;
        }

        match &self.0.body {
            syn_solidity::FunctionBody::Empty(_) => write!(f, ";")?,
            syn_solidity::FunctionBody::Block(block) => {
                write!(f, "{{")?;
                for stmt in &block.stmts {
                    if let syn_solidity::Stmt::Return(inner_return) = stmt {
                        write!(f, "return ")?;
                        if let Some(expr) = inner_return.expr.clone() {
                            if let Ok(res) = fmt_call(&expr) {
                                write!(f, "{res}")?;
                            } else {
                                write!(f, "<expr> ")?;
                            }
                        }
                    }
                }
                write!(f, "; }}\n")?;
            }
        }

        Ok(())
    }
}
