//! Retry config, strategy and middleware for using on `HttpClient` side
use std::num::NonZeroU32;
use reqwest_retry::{DefaultRetryableStrategy, RetryTransientMiddleware};
use retry_policies::RetryDecision;
use retry_policies::policies::ExponentialBackoff;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};

/// HTTP client retry policy kind (base or exponential)
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RetryPolicyKind {
    /// Base backoff policy for retry
    #[serde(alias = "backoff", alias = "backoff_policy")]
    Base(BaseBackoffPolicy),
    /// Exponential backoff policy for retry
    #[serde(alias = "exponential_backoff", alias = "exponential_backoff_policy")]
    Exponential(ExponentialBackoffPolicy),
}

/// HTTP client Base backoff policy for retry
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct BaseBackoffPolicy {
    /// Number of attempts to retry failed request
    #[serde(alias = "attempts")]
    max_attempts: NonZeroU32,
    /// Backoff duration
    #[serde(alias = "duration", with = "humantime_serde")]
    backoff_duration: Duration,
}

/// HTTP client Exponential backoff policy for retry
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

impl retry_policies::RetryPolicy for BaseBackoffPolicy {
    fn should_retry(&self, _req_start_time: SystemTime, n_past_retries: u32) -> RetryDecision {
        if n_past_retries < self.max_attempts.into() {
            return RetryDecision::Retry {
                execute_after: SystemTime::now() + self.backoff_duration,
            };
        }
        RetryDecision::DoNotRetry
    }
}

/// Retry middleware based on Base backoff policy
/// and default Retryable strategy
pub type BaseRetryMiddleware =
    RetryTransientMiddleware<BaseBackoffPolicy, DefaultRetryableStrategy>;

impl From<BaseBackoffPolicy> for BaseRetryMiddleware {
    fn from(policy: BaseBackoffPolicy) -> Self {
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
    use std::time::Duration;

    #[rstest]
    #[case(
        r#"{
            "backoff": {
                "attempts": 5,
                "duration": "3s"
            }
        }"#,
        RetryPolicyKind::Base(BaseBackoffPolicy {
            max_attempts: NonZeroU32::new(5).unwrap(),
            backoff_duration: Duration::from_secs(3)})
    )]
    #[case(
        r#"{
            "backoff_policy": {
                "max_attempts": 5,
                "backoff_duration": "3s"
            }
        }"#,
        RetryPolicyKind::Base(BaseBackoffPolicy {
            max_attempts: NonZeroU32::new(5).unwrap(),
            backoff_duration: Duration::from_secs(3)})
    )]
    #[case(
        r#"{
            "exponential_backoff": {
                "attempts": 5,
                "min_duration": "1s",
                "max_duration": "3s"
            }
        }"#,
        RetryPolicyKind::Exponential(ExponentialBackoffPolicy {
            max_attempts: NonZeroU32::new(5).unwrap(),
            min_backoff_duration: Duration::from_secs(1),
            max_backoff_duration: Duration::from_secs(3)})
    )]
    #[case(
        r#"{
            "exponential_backoff_policy": {
                "max_attempts": 5,
                "min_backoff_duration": "1s",
                "max_backoff_duration": "3s"
            }
        }"#,
        RetryPolicyKind::Exponential(ExponentialBackoffPolicy {
            max_attempts: NonZeroU32::new(5).unwrap(),
            min_backoff_duration: Duration::from_secs(1),
            max_backoff_duration: Duration::from_secs(3)})
    )]
    fn test_retry_policy_deserialization_ok(
        #[case] cfg_json: &str,
        #[case] expected_policy: RetryPolicyKind,
    ) {
        let policy = serde_json::from_str::<RetryPolicyKind>(cfg_json);
        assert!(policy.is_ok(), "Config was not deserialized properly");
        assert_eq!(policy.unwrap(), expected_policy);
    }

    #[rstest]
    #[case(
        r#"{
            "backoff_policy": {
                "max_attempts": -1,
                "backoff_duration": "2s"
            }
        }"#,
        "invalid value: integer `-1`, expected a nonzero u32"
    )]
    #[case(
        r#"{
            "backoff_policy": {
                "max_attempts": 0,
                "backoff_duration": "2s"
            }
        }"#,
        "invalid value: integer `0`, expected a nonzero u32"
    )]
    #[case(
        r#"{
            "backoff_policy": {
                "max_attempts": 1,
                "backoff_duration": "2"
            }
        }"#,
        "invalid value: string \"2\", expected a duration"
    )]
    #[case(
        r#"{
            "exponential_backoff_policy": {
                "max_attempts": -1,
                "min_backoff_duration": "2s",
                "max_backoff_duration": "3s"
            }
        }"#,
        "invalid value: integer `-1`, expected a nonzero u32"
    )]
    #[case(
        r#"{
            "exponential_backoff_policy": {
                "max_attempts": 0,
                "min_backoff_duration": "2s",
                "max_backoff_duration": "3s"
            }
        }"#,
        "invalid value: integer `0`, expected a nonzero u32"
    )]
    #[case(
        r#"{
            "exponential_backoff_policy": {
                "max_attempts": 1,
                "min_backoff_duration": "2",
                "max_backoff_duration": "3s"
            }
        }"#,
        "invalid value: string \"2\", expected a duration"
    )]
    #[case(
        r#"{
            "exponential_backoff_policy": {
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
        let policy = serde_json::from_str::<RetryPolicyKind>(cfg_json);
        assert!(policy.is_err());
        let err_str = policy.unwrap_err().to_string();
        assert!(
            err_str.starts_with(expected_err_str),
            "{}",
            format!(
                "error string '{}' should start with substring: {}",
                err_str, expected_err_str,
            )
        )
    }
}
