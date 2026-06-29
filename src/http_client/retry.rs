//! Retry config, strategy and middleware for using on `HttpClient` side
use reqwest_retry::{DefaultRetryableStrategy, RetryTransientMiddleware};
use retry_policies::RetryDecision;
use retry_policies::policies::ExponentialBackoff;
use serde::{Deserialize, Serialize};
use std::num::NonZeroU32;
use std::time::{Duration, SystemTime};

/// HTTP client retry policy kind (base or exponential)
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RetryPolicyKind {
    /// Base backoff policy for retry
    #[serde(alias = "fixed")]
    FixedInterval(FixedIntervalPolicy),
    /// Exponential backoff policy for retry
    #[serde(alias = "exponential")]
    ExponentialBackoff(ExponentialBackoffPolicy),
}

/// HTTP client retry policy with fixed interval between attempts
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct FixedIntervalPolicy {
    /// Number of attempts to retry failed request
    #[serde(alias = "attempts")]
    max_attempts: NonZeroU32,
    /// Duration between retry attempts
    #[serde(with = "humantime_serde")]
    duration: Duration,
}

/// HTTP client retry policy with exponential backoff
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct ExponentialBackoffPolicy {
    /// Number of attempts to retry failed request
    #[serde(alias = "attempts")]
    max_attempts: NonZeroU32,
    /// Min backoff duration
    #[serde(alias = "min_duration", with = "humantime_serde")]
    min_backoff_duration: Duration,
    /// Max backoff duration
    #[serde(alias = "max_duration", with = "humantime_serde")]
    max_backoff_duration: Duration,
}

impl retry_policies::RetryPolicy for FixedIntervalPolicy {
    fn should_retry(&self, _req_start_time: SystemTime, n_past_retries: u32) -> RetryDecision {
        if n_past_retries < self.max_attempts.into() {
            return RetryDecision::Retry {
                execute_after: SystemTime::now() + self.duration,
            };
        }
        RetryDecision::DoNotRetry
    }
}

/// Retry middleware based on Base backoff policy
/// and default Retryable strategy
pub type BaseRetryMiddleware =
    RetryTransientMiddleware<FixedIntervalPolicy, DefaultRetryableStrategy>;

impl From<FixedIntervalPolicy> for BaseRetryMiddleware {
    fn from(policy: FixedIntervalPolicy) -> Self {
        RetryTransientMiddleware::new_with_policy(policy)
    }
}

/// Retry middleware based on Exponential backoff policy
/// and default Retryable strategy
pub type ExponentialRetryMiddleware =
    RetryTransientMiddleware<ExponentialBackoff, DefaultRetryableStrategy>;

impl From<ExponentialBackoffPolicy> for ExponentialRetryMiddleware {
    fn from(policy: ExponentialBackoffPolicy) -> Self {
        let policy = ExponentialBackoff::builder()
            .retry_bounds(policy.min_backoff_duration, policy.max_backoff_duration)
            .build_with_max_retries(policy.max_attempts.into());
        RetryTransientMiddleware::new_with_policy(policy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::*;

    #[derive(Debug, Clone, Eq, PartialEq, Deserialize)]
    struct TestCfg {
        retry: Option<RetryPolicyKind>,
    }

    macro_rules! get_config_with_policy {
        (kind = "fixed"; $n:expr, $dur:expr) => {{
            TestCfg {
                retry: Some(RetryPolicyKind::FixedInterval(FixedIntervalPolicy {
                    max_attempts: NonZeroU32::new($n).expect("invalid u32"),
                    duration: std::time::Duration::from_secs($dur),
                })),
            }
        }};
        (kind = "exponent"; $n:expr, $min_dur:expr, $max_dur:expr) => {{
            TestCfg {
                retry: Some(RetryPolicyKind::ExponentialBackoff(
                    ExponentialBackoffPolicy {
                        max_attempts: NonZeroU32::new($n).expect("invalid u32"),
                        min_backoff_duration: std::time::Duration::from_secs($min_dur),
                        max_backoff_duration: std::time::Duration::from_secs($max_dur),
                    },
                )),
            }
        }};
    }

    #[rstest]
    #[case("{}", TestCfg { retry: None })]
    #[case(
        r#"{
            "retry": {
                "kind": "fixed",
                "attempts": 5,
                "duration": "3s"
            }
        }"#,
        get_config_with_policy!(kind = "fixed"; 5, 3)
    )]
    #[case(
        r#"{
            "retry": {
                "kind": "fixed_interval",
                "max_attempts": 5,
                "duration": "3s"
            }
        }"#,
        get_config_with_policy!(kind = "fixed"; 5, 3)
    )]
    #[case(
        r#"{
            "retry": {
                "kind": "exponential",
                "attempts": 5,
                "min_duration": "1s",
                "max_duration": "3s"
            }
        }"#,
        get_config_with_policy!(kind = "exponent"; 5, 1, 3),
    )]
    #[case(
        r#"{
            "retry": {
                "kind": "exponential_backoff",
                "max_attempts": 5,
                "min_backoff_duration": "1s",
                "max_backoff_duration": "3s"
            }
        }"#,
        get_config_with_policy!(kind = "exponent"; 5, 1, 3),
    )]
    fn test_retry_policy_deserialization_ok(
        #[case] cfg_json: &str,
        #[case] expected_config: TestCfg,
    ) {
        let cfg = serde_json::from_str::<TestCfg>(cfg_json);
        assert!(cfg.is_ok(), "Config was not deserialized properly");
        assert_eq!(cfg.unwrap(), expected_config);
    }

    #[rstest]
    #[case(
        r#"{
            "retry": {
                "kind": "fixed_interval",
                "max_attempts": -1,
                "duration": "2s"
            }
        }"#,
        "invalid value: integer `-1`, expected a nonzero u32"
    )]
    #[case(
        r#"{
            "retry": {
                "kind": "fixed_interval",
                "max_attempts": 0,
                "duration": "2s"
            }
        }"#,
        "invalid value: integer `0`, expected a nonzero u32"
    )]
    #[case(
        r#"{
            "retry": {
                "kind": "fixed_interval",
                "attempts": 1,
                "duration": "2"
            }
        }"#,
        "invalid value: string \"2\", expected a duration"
    )]
    #[case(
        r#"{
            "retry": {
                "kind": "exponential_backoff",
                "max_attempts": -1,
                "min_backoff_duration": "2s",
                "max_backoff_duration": "3s"
            }
        }"#,
        "invalid value: integer `-1`, expected a nonzero u32"
    )]
    #[case(
        r#"{
            "retry": {
                "kind": "exponential_backoff",
                "max_attempts": 0,
                "min_backoff_duration": "2s",
                "max_backoff_duration": "3s"
            }
        }"#,
        "invalid value: integer `0`, expected a nonzero u32"
    )]
    #[case(
        r#"{
            "retry": {
                "kind": "exponential_backoff",
                "max_attempts": 1,
                "min_backoff_duration": "2",
                "max_backoff_duration": "2s"
            }
        }"#,
        "invalid value: string \"2\", expected a duration"
    )]
    #[case(
        r#"{
            "retry": {
                "kind": "exponential_backoff",
                "max_attempts": 1,
                "min_backoff_duration": "2s",
                "max_backoff_duration": "3"
            }
        }"#,
        "invalid value: string \"3\", expected a duration"
    )]
    fn test_retry_policy_deserialization_error(
        #[case] cfg_json: &str,
        #[case] expected_err_str: &str,
    ) {
        let cfg = serde_json::from_str::<TestCfg>(cfg_json);
        assert!(cfg.is_err(), "config was deserialized OK unexpectedly");
        let err_str = cfg.unwrap_err().to_string();
        assert!(
            err_str.starts_with(expected_err_str),
            "{}",
            format!(
                "error string '{}' should start with substring: '{}'",
                err_str, expected_err_str,
            )
        )
    }
}
