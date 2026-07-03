//! String manipulation helper functions.

use std::borrow::Cow;

/// Escape text for use as a quoted string inside HTTP headers.
pub(crate) fn escape_http_quoted<'a>(input: &'a str) -> Cow<'a, str> {
    let num_escapes = input.chars().filter(|ch| matches!(ch, '\\' | '"')).count();
    if num_escapes > 0 {
        let mut output = String::with_capacity(input.len() + num_escapes);
        for ch in input.chars() {
            if matches!(ch, '\\' | '"') {
                output.push('\\');
            }
            output.push(ch);
        }
        Cow::Owned(output)
    } else {
        Cow::Borrowed(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case::empty("", Cow::Borrowed(""))]
    #[case::no_escapes("test string!", Cow::Borrowed("test string!"))]
    #[case::escaped_quote("symbol \" is escaped", Cow::Owned("symbol \\\" is escaped".into()))]
    #[case::escaped_bslash("symbol \\ is escaped", Cow::Owned("symbol \\\\ is escaped".into()))]
    fn test_escape_http_quoted(#[case] input: &str, #[case] expected: Cow<'_, str>) {
        let output = escape_http_quoted(input);
        assert_eq!(output, expected);
    }
}
