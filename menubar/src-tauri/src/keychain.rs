// Platform keychain wrapper. Uses the `keyring` crate which abstracts:
// - macOS: Keychain Services
// - Linux: Secret Service (libsecret) when available
// - Windows: Credential Manager

use keyring::Entry;

const SERVICE: &str = "com.sanctuaryprotocol.menubar";
const ACCOUNT_AUTH_TOKEN: &str = "fortress-auth-token";

pub fn set_auth_token(token: &str) -> Result<(), keyring::Error> {
    let entry = Entry::new(SERVICE, ACCOUNT_AUTH_TOKEN)?;
    entry.set_password(token)
}

pub fn get_auth_token() -> Result<Option<String>, keyring::Error> {
    let entry = Entry::new(SERVICE, ACCOUNT_AUTH_TOKEN)?;
    match entry.get_password() {
        Ok(p) => Ok(Some(p)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(e),
    }
}
