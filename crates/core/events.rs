//! Lifecycle events published by allowthem's route handlers.
//!
//! See `docs/superpowers/specs/2026-04-20-lifecycle-events-design.md` for the
//! full contract. Summary: fire-and-forget, at-most-once, owned `'static` data,
//! integrator owns recovery.

use chrono::{DateTime, Utc};
use tokio::sync::mpsc;

use crate::types::User;

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum AuthEvent {
    Registered(RegisteredEvent),
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RegisteredEvent {
    pub user: User,
    pub source: RegistrationSource,
    pub ctx: EventContext,
}

impl RegisteredEvent {
    /// Constructor used by allowthem's route handlers. Integrators receive
    /// `RegisteredEvent` values from the channel and should not construct
    /// them directly.
    pub fn new(user: User, source: RegistrationSource, ctx: EventContext) -> Self {
        Self { user, source, ctx }
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum RegistrationSource {
    Password,
    OAuth { provider: String },
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct EventContext {
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub base_url: String,
    pub occurred_at: DateTime<Utc>,
}

impl EventContext {
    /// Constructor used by allowthem's route handlers. Integrators receive
    /// `EventContext` values from the channel and should not construct them
    /// directly.
    pub fn new(
        ip: Option<String>,
        user_agent: Option<String>,
        base_url: String,
        occurred_at: DateTime<Utc>,
    ) -> Self {
        Self {
            ip,
            user_agent,
            base_url,
            occurred_at,
        }
    }
}

pub type AuthEventSender = mpsc::UnboundedSender<AuthEvent>;
pub type AuthEventReceiver = mpsc::UnboundedReceiver<AuthEvent>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Email, UserId};

    fn sample_user() -> User {
        User {
            id: UserId::new(),
            email: Email::new("test@example.com".into()).unwrap(),
            username: None,
            password_hash: None,
            email_verified: false,
            is_active: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            custom_data: None,
        }
    }

    #[test]
    fn registered_event_constructs_and_clones() {
        let event = AuthEvent::Registered(RegisteredEvent::new(
            sample_user(),
            RegistrationSource::Password,
            EventContext::new(
                Some("127.0.0.1".into()),
                Some("test-agent".into()),
                "http://test".into(),
                Utc::now(),
            ),
        ));

        let cloned = event.clone();
        // Debug-format should work on the cloned value.
        let _ = format!("{cloned:?}");
    }

    #[test]
    fn oauth_source_carries_provider() {
        let source = RegistrationSource::OAuth {
            provider: "mock".into(),
        };
        let _ = format!("{source:?}");
        let cloned = source.clone();
        match cloned {
            RegistrationSource::OAuth { provider } => assert_eq!(provider, "mock"),
            _ => panic!("expected OAuth variant"),
        }
    }
}
