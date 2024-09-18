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
    let base =
        if s.is_empty() { String::new() } else { format!("{}{}", s[..1].to_lowercase(), &s[1..]) };
    if is_arr {
        format!("{}Array", base)
    } else {
        base
    }
}
/// Ensures the first letter of a string is uppercase.
///
/// # Arguments
///
/// * `s` - A string slice that you want to capitalize.
///
/// # Returns
///
/// * `Ok(String)` - A new String with the first letter capitalized.
/// * `Err(String)` - An error message if the operation couldn't be performed.
///
/// # Examples
///
/// ```
/// let result = ensure_first_letter_uppercase("hello");
/// assert_eq!(result, Ok("Hello".to_string()));
///
/// let result = ensure_first_letter_uppercase("Hello");
/// assert_eq!(result, Ok("Hello".to_string()));
///
/// let result = ensure_first_letter_uppercase("");
/// assert!(result.is_err());
/// ```
pub fn ensure_first_letter_uppercase(s: &str) -> Result<String, String> {
    if s.is_empty() {
        return Err("Cannot capitalize an empty string".to_string());
    }

    let mut chars = s.chars();
    match chars.next() {
        None => Err("Unexpected error: string is empty".to_string()),
        Some(first_char) => {
            let capitalized = first_char.to_uppercase().collect::<String>() + chars.as_str();
            Ok(capitalized)
        }
    }
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

    #[test]
    fn test_ensure_first_letter_uppercase() {
        assert_eq!(ensure_first_letter_uppercase("hello"), Ok("Hello".to_string()));
        assert_eq!(ensure_first_letter_uppercase("Hello"), Ok("Hello".to_string()));
        assert_eq!(ensure_first_letter_uppercase("HELLO"), Ok("HELLO".to_string()));
        assert_eq!(ensure_first_letter_uppercase("h"), Ok("H".to_string()));
        assert_eq!(ensure_first_letter_uppercase("123abc"), Ok("123abc".to_string()));
        assert!(ensure_first_letter_uppercase("").is_err());
    }
}
