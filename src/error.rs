use std::io::{self, ErrorKind};

use zbus::{
    fdo,
    message::{self, Header},
    names::ErrorName,
    DBusError, Message,
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O Error: {0}")]
    Io(#[from] io::Error),
    #[error("D-Bus Error: {0}")]
    Dbus(#[from] zbus::Error),
    #[error("ReDB Error: {0}")]
    Redb(#[source] Box<redb::Error>),
    #[error("Secret encryption error: {0}")]
    Encryption(&'static str),
    #[error("GPG Error: {0}")]
    Gpg(String),
    #[error("Pass is not initialized")]
    NotInitialized,
    #[error("Invalid secret service session")]
    InvalidSession,
    #[error("Access denied")]
    PermissionDenied,
}

impl DBusError for Error {
    fn create_reply(&self, msg: &Header<'_>) -> zbus::Result<Message> {
        let name = self.name();
        #[allow(deprecated)]
        let msg = message::Builder::error(msg, name)?;
        match self {
            Error::Io(e) => msg.build(&(e.to_string(),)),
            Error::Dbus(e) => msg.build(&(e.to_string(),)),
            Error::Redb(e) => msg.build(&(e.to_string(),)),
            Error::Gpg(e) => msg.build(&(e,)),
            _ => msg.build(&()),
        }
    }

    fn name(&self) -> ErrorName<'_> {
        ErrorName::from_static_str_unchecked(match self {
            Error::Io(e) if e.kind() == ErrorKind::NotFound => {
                "org.freedesktop.Secret.Error.NoSuchObject"
            }
            Error::Io(_) => "org.freedesktop.DBus.Error.IOError",
            Error::Dbus(_) => "org.freedesktop.zbus.Error",
            Error::Redb(_) => "me.grimsteel.PassSecretService.ReDBError",
            Error::Gpg(_) => "me.grimsteel.PassSecretService.GPGError",
            Error::Encryption(_) => "me.grimsteel.PassSecretService.EncryptionError",
            Error::NotInitialized => "me.grimsteel.PassSecretService.PassNotInitialized",
            Error::InvalidSession => "org.freedesktop.Secret.Error.NoSession",
            Error::PermissionDenied => "org.freedesktop.DBus.Error.AccessDenied",
        })
    }

    fn description(&self) -> Option<&str> {
        match self {
            Error::Dbus(zbus::Error::MethodError(_, desc, _)) => desc.as_deref(),
            Error::Gpg(e) => Some(e.as_str()),
            _ => None,
        }
    }
}

impl From<Error> for fdo::Error {
    fn from(value: Error) -> Self {
        match value {
            Error::Io(err) => Self::IOError(format!("{err}")),
            Error::Dbus(err) => Self::ZBus(err),
            Error::PermissionDenied => Self::AccessDenied("Access denied".into()),
            err => Self::Failed(format!("{err}")),
        }
    }
}

impl From<redb::Error> for Error {
    fn from(value: redb::Error) -> Self {
        Self::Redb(Box::new(value))
    }
}

pub type Result<T = ()> = std::result::Result<T, Error>;

pub trait IntoResult<T> {
    fn into_result(self) -> Result<T>;
}

impl<T, E: Into<redb::Error>> IntoResult<T> for std::result::Result<T, E> {
    fn into_result(self) -> Result<T> {
        self.map_err(|e| Into::<redb::Error>::into(e).into())
    }
}

pub trait OptionNoneNotFound<T> {
    fn into_not_found(self) -> Result<T>;
}

impl<T> OptionNoneNotFound<T> for Option<T> {
    fn into_not_found(self) -> Result<T> {
        self.ok_or(io::Error::from(io::ErrorKind::NotFound).into())
    }
}

macro_rules! raise_nonexistent_table {
    ($expression:expr) => {
        raise_nonexistent_table!(
            $expression,
            Err(io::Error::from(io::ErrorKind::NotFound).into())
        )
    };
    ($expression:expr, $default:expr) => {
        match $expression {
            Ok(t) => t,
            // table does not exist yet - that's ok
            Err(redb::TableError::TableDoesNotExist(_)) => {
                return $default;
            }
            Err(e) => return Err(e).into_result(),
        }
    };
}
pub(crate) use raise_nonexistent_table;
