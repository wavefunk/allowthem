pub mod db;
pub mod email;
pub mod error;
pub mod handle;
pub mod password;
pub mod permissions;
pub mod roles;
pub mod sessions;
pub mod types;
pub mod users;

pub use db::Db;
pub use email::{EmailMessage, EmailSender, LogEmailSender};
pub use error::AuthError;
pub use handle::{AllowThem, AllowThemBuilder, BuildError};
pub use sessions::{
    SessionConfig, generate_token, hash_token, parse_session_cookie, session_cookie,
};
pub use types::*;

#[cfg(test)]
mod db_tests;
