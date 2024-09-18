//! Types used in the CLI.

use std::fmt::Display;
use syn_solidity::{
    ArgListImpl, Expr, ExprPostfix, ForInitStmt, ItemFunction, Lit, Stmt, StmtVarDecl, VarDeclDecl,
    VariableDefinition,
};

pub(crate) type BytesU32 = std::num::NonZero<u16>;

/// To implement `Display` for `VariableDefinition`.
pub(crate) struct VariableDefinitionWrapper(pub(crate) VariableDefinition);

impl Display for VariableDefinitionWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {} {}", self.0.ty, self.0.attributes, self.0.name)?;
        if let Some((_, expr)) = &self.0.initializer {
            write!(f, " = ")?;
            if let Ok(res) = fmt_expr(expr) {
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

                for stmt in block.stmts.iter() {
                    if let Ok(res) = fmt_stmt(stmt) {
                        write!(f, "{}", res)?;
                    }
                }

                write!(f, "}}")?;
            }
        }

        Ok(())
    }
}

/// [Display] implementation specifically for handling [Expr]
pub(crate) fn fmt_expr(call: &Expr) -> eyre::Result<String> {
    let mut result = String::new();
    match call {
        Expr::Lit(lit) => match lit {
            Lit::Str(string) => result.push_str(&format!("\"{}\"", string.to_string())),
            _ => return Err(eyre::Report::msg("Unsupported literal type")),
        },
        Expr::Ident(ident) => result.push_str(&ident.to_string()),
        Expr::Call(call) => {
            let expr_str = fmt_expr(&call.expr)?;
            result.push_str(&expr_str);
            result.push('(');
            if let ArgListImpl::Unnamed(args) = &call.args.list {
                for (i, arg) in args.iter().enumerate() {
                    let arg_str = fmt_expr(arg)?;
                    result.push_str(&arg_str);
                    if i < args.len() - 1 {
                        result.push(',');
                        result.push(' ');
                    }
                }
            }
            result.push(')');
        }
        Expr::Member(member) => {
            let expr_str = fmt_expr(&member.expr)?;
            result.push_str(&expr_str);

            result.push('.');

            let member_str = fmt_expr(&member.member)?;
            result.push_str(&member_str);
        }
        Expr::Index(index) => {
            let expr_str = fmt_expr(&index.expr)?;
            result.push_str(&expr_str);
            result.push('[');
            if let Some(start) = &index.start {
                result.push_str(&fmt_expr(start).unwrap_or_else(|_| "<expr>".to_string()));
            }
            if let Some(_) = &index.colon_token {
                result.push_str(":");
            }
            if let Some(end) = &index.end {
                result.push_str(&fmt_expr(end).unwrap_or_else(|_| "<expr>".to_string()));
            }

            result.push(']');
        }
        Expr::Binary(binary) => {
            let left_str = fmt_expr(&binary.left)?;
            result.push_str(&left_str);
            result.push_str(&binary.op.to_string());
            let right_str = fmt_expr(&binary.right)?;
            result.push_str(&right_str);
        }
        Expr::Unary(unary) => {
            result.push_str(&unary.op.to_string());
            let expr_str = fmt_expr(&unary.expr)?;
            result.push_str(&expr_str);
        }
        Expr::New(new) => {
            result.push_str("new ");
            result.push_str(&new.ty.to_string());
        }
        Expr::Postfix(ExprPostfix { expr, op }) => {
            result.push_str(&fmt_expr(&expr).unwrap_or_else(|_| "<expr>".to_string()));
            result.push_str(&op.to_string());
        }
        _ => return Err(eyre::Report::msg("Unsupported expression type")),
    }

    Ok(result)
}

/// Display for `Stmt`
pub(crate) fn fmt_stmt(stmt: &Stmt) -> eyre::Result<String> {
    let mut result = String::new();
    match stmt {
        syn_solidity::Stmt::Return(inner_return) => {
            result.push_str("return ");
            if let Some(expr) = inner_return.expr.clone() {
                result.push_str(&fmt_expr(&expr)?);
            }
            result.push(';');
        }
        syn_solidity::Stmt::VarDecl(stmt_var_decl) => {
            result.push_str(&fmt_stmt_var_decl(stmt_var_decl)?);
        }
        syn_solidity::Stmt::Expr(expr) => {
            result.push_str(&fmt_expr(&expr.expr)?);
        }
        syn_solidity::Stmt::For(for_stmt) => {
            result.push_str("for (");
            match &for_stmt.init {
                ForInitStmt::Expr(expr) => {
                    result.push_str(&fmt_expr(&expr.expr)?);
                    result.push(';');
                }
                ForInitStmt::VarDecl(var_decl) => {
                    result.push_str(&fmt_stmt_var_decl(var_decl)?);
                }
                ForInitStmt::Empty(_) => {}
            };

            if let Some(cond) = &for_stmt.cond {
                result.push_str(&fmt_expr(cond)?);
            }

            result.push(';');

            if let Some(post) = &for_stmt.post {
                result.push_str(&fmt_expr(post)?);
            }

            result.push(')');
            result.push_str(&fmt_stmt(&for_stmt.body)?);
        }
        Stmt::Block(block) => {
            result.push_str(" {");
            for stmt in block.stmts.iter() {
                result.push_str(&fmt_stmt(stmt)?);
            }
            result.push(';');
            result.push_str(" }");
        }
        _ => todo!(),
    }

    Ok(result)
}

/// To implement `Display` for `StmtVarDecl`.
pub(crate) fn fmt_stmt_var_decl(
    StmtVarDecl { declaration, assignment, semi_token }: &StmtVarDecl,
) -> eyre::Result<String> {
    let mut result = String::new();
    if let VarDeclDecl::VarDecl(var_decl) = declaration {
        result.push_str(&var_decl.to_string());
    }
    if let Some(assignment) = assignment {
        result.push_str(" = ");
        result.push_str(&fmt_expr(&assignment.1)?);
    }

    result.push(';');

    Ok(result)
}
