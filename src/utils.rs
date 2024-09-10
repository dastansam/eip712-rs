/// Converts camel case to uppercase with underscores.
///
/// Example:
///
/// ```
/// camel_to_uppercase("camelCaseString"); // "CAMEL_CASE_STRING"
/// ```
pub(crate) fn camel_to_uppercase(s: &str) -> String {
    let mut result = String::new();
    let mut prev_char_is_lowercase = false;

    for (i, c) in s.char_indices() {
        if i > 0 && c.is_uppercase() && prev_char_is_lowercase {
            result.push('_');
        }
        result.push(c.to_ascii_uppercase());
        prev_char_is_lowercase = c.is_lowercase();
    }

    result
}

/// Converts camel case to a param name in Solidity.
///
/// Example:
///
/// ```
/// struct_to_param_name("CamelCaseString"); // "camelCaseString"
/// struct_to_param_name("CamelCaseString", true); // "camelCaseStringArray"
/// ```
pub fn struct_to_param_name(s: &str, is_arr: bool) -> String {
    format!("{}{}{}", s[..1].to_lowercase(), &s[1..], if is_arr { "Array" } else { "" })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_camel_to_uppercase_with_underscores() {
        assert_eq!(camel_to_uppercase("camelCaseString"), "CAMEL_CASE_STRING");
        assert_eq!(
            camel_to_uppercase("camelCaseStringWithNumbers123"),
            "CAMEL_CASE_STRING_WITH_NUMBERS123"
        );
    }

    #[test]
    fn test_struct_to_param_name() {
        assert_eq!(struct_to_param_name("camelCaseString", false), "camelCaseString");
        assert_eq!(struct_to_param_name("camelCaseString", true), "camelCaseStringArray");
    }
}
