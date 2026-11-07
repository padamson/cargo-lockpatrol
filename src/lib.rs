// Template placeholder. Replace with your crate's implementation; the
// shapes below (a decision returned as a value, an error variant that
// names the offending input, an injected environment) are the ones the
// tests are written against.

use std::fmt;

/// How big a collection of `count` items is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Size {
    Empty,
    Small,
    Large,
}

/// A count that cannot be classified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SizeError {
    /// The count was negative; the value is carried so the caller can say
    /// which one.
    Negative(i64),
}

impl fmt::Display for SizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SizeError::Negative(n) => write!(f, "count {n} is negative"),
        }
    }
}

impl std::error::Error for SizeError {}

/// The environment variable that overrides [`DEFAULT_LARGE_THRESHOLD`].
pub const LARGE_THRESHOLD_VAR: &str = "MY_PROJECT_LARGE_THRESHOLD";

/// Counts at or above this are [`Size::Large`] unless the environment
/// says otherwise.
pub const DEFAULT_LARGE_THRESHOLD: i64 = 10;

/// Classify `count` with the default threshold.
///
/// ```
/// use my_project::{classify, Size, SizeError};
///
/// assert_eq!(classify(0), Ok(Size::Empty));
/// assert_eq!(classify(10), Ok(Size::Large));
/// assert_eq!(classify(-1), Err(SizeError::Negative(-1)));
/// ```
pub fn classify(count: i64) -> Result<Size, SizeError> {
    classify_with(count, DEFAULT_LARGE_THRESHOLD)
}

/// Classify `count`: zero is empty, anything from `large_threshold` up is
/// large, everything in between is small.
pub fn classify_with(count: i64, large_threshold: i64) -> Result<Size, SizeError> {
    if count < 0 {
        return Err(SizeError::Negative(count));
    }
    if count == 0 {
        Ok(Size::Empty)
    } else if count >= large_threshold {
        Ok(Size::Large)
    } else {
        Ok(Size::Small)
    }
}

/// The large threshold, read through `env` so tests can pass a fixed map
/// instead of mutating the process environment (`std::env::set_var` is
/// unsafe under parallel tests). An unset, empty, unparsable, or
/// non-positive value falls back to [`DEFAULT_LARGE_THRESHOLD`]: a
/// threshold of zero or less would make every non-empty count large and
/// `Small` unreachable, which is a typo, not a setting.
pub fn large_threshold(env: impl Fn(&str) -> Option<String>) -> i64 {
    env(LARGE_THRESHOLD_VAR)
        .filter(|v| !v.trim().is_empty())
        .and_then(|v| v.trim().parse().ok())
        .filter(|t: &i64| *t > 0)
        .unwrap_or(DEFAULT_LARGE_THRESHOLD)
}

/// [`large_threshold`] read from the real process environment.
pub fn large_threshold_from_process_env() -> i64 {
    large_threshold(|key| std::env::var(key).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_of<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |key| {
            pairs
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| v.to_string())
        }
    }

    #[test]
    fn zero_items_is_empty() {
        assert_eq!(classify(0), Ok(Size::Empty));
    }

    #[test]
    fn one_below_the_threshold_is_small() {
        assert_eq!(classify(DEFAULT_LARGE_THRESHOLD - 1), Ok(Size::Small));
    }

    #[test]
    fn the_threshold_itself_is_large() {
        // Kills `replace >= with <`, the one mutant cargo-mutants emits
        // for this operator: 10 < 10 is false, so the threshold lands in
        // Small.
        assert_eq!(classify(DEFAULT_LARGE_THRESHOLD), Ok(Size::Large));
    }

    #[test]
    fn a_negative_count_is_an_error_naming_the_count() {
        match classify(-3) {
            Err(SizeError::Negative(n)) => assert_eq!(n, -3),
            other => panic!("expected Negative, got {other:?}"),
        }
    }

    #[test]
    fn the_error_message_names_the_count() {
        let msg = SizeError::Negative(-3).to_string();
        assert!(
            msg.contains("-3"),
            "message must carry the value; got: {msg}"
        );
    }

    #[test]
    fn an_explicit_threshold_wins_over_the_default() {
        assert_eq!(classify_with(3, 3), Ok(Size::Large));
    }

    #[test]
    fn the_threshold_comes_from_the_environment_when_set() {
        assert_eq!(large_threshold(env_of(&[(LARGE_THRESHOLD_VAR, "3")])), 3);
    }

    #[test]
    fn an_unset_threshold_falls_back_to_the_default() {
        assert_eq!(large_threshold(env_of(&[])), DEFAULT_LARGE_THRESHOLD);
    }

    #[test]
    fn an_empty_threshold_counts_as_unset() {
        // The boundary the code special-cases: `Some("")` is not a value.
        assert_eq!(
            large_threshold(env_of(&[(LARGE_THRESHOLD_VAR, "  ")])),
            DEFAULT_LARGE_THRESHOLD
        );
    }

    #[test]
    fn a_non_positive_threshold_falls_back_to_the_default() {
        // Zero would make Small unreachable; `> 0` mutated to `>= 0` lets it through.
        for value in ["0", "-5"] {
            assert_eq!(
                large_threshold(env_of(&[(LARGE_THRESHOLD_VAR, value)])),
                DEFAULT_LARGE_THRESHOLD,
                "threshold {value} must fall back"
            );
        }
    }

    #[test]
    fn a_threshold_of_one_is_the_smallest_accepted() {
        // The boundary of the `> 0` filter: 1 is a real setting, 0 is not.
        assert_eq!(large_threshold(env_of(&[(LARGE_THRESHOLD_VAR, "1")])), 1);
    }

    #[test]
    fn the_process_env_wrapper_reads_the_same_variable_as_the_seam() {
        // Guards the wiring only: the wrapper must delegate to the seam
        // over the real environment, whatever that environment holds.
        // Every claim about the parsing lives in the tests above.
        assert_eq!(
            large_threshold_from_process_env(),
            large_threshold(|key| std::env::var(key).ok())
        );
    }

    #[test]
    fn an_unparsable_threshold_falls_back_to_the_default() {
        assert_eq!(
            large_threshold(env_of(&[(LARGE_THRESHOLD_VAR, "ten")])),
            DEFAULT_LARGE_THRESHOLD
        );
    }
}
