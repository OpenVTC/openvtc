//! A text buffer for a passphrase being typed.

use secrecy::SecretString;
use zeroize::{Zeroize, Zeroizing};

/// Holds a passphrase as it is typed, keystroke by keystroke, without leaving
/// copies of it behind.
///
/// A plain `String` grown by `push` reallocates as it fills, and every
/// reallocation frees the old block with the passphrase-so-far still in it;
/// `clear` and `mem::take` leave the bytes in place too. Here a growth copies
/// into a new zeroizing buffer and wipes the old one, `clear` wipes, and the
/// finished passphrase leaves as a [`SecretString`].
#[derive(Default)]
pub(crate) struct SecretBuffer(Zeroizing<String>);

/// Room for a long passphrase before the first growth.
const INITIAL_CAPACITY: usize = 128;

impl SecretBuffer {
    /// Append `s`, growing into a fresh buffer (and wiping the old) when full.
    pub(crate) fn push_str(&mut self, s: &str) {
        let needed = self.0.len() + s.len();
        if needed > self.0.capacity() {
            let mut grown = Zeroizing::new(String::with_capacity(
                needed.max(self.0.capacity() * 2).max(INITIAL_CAPACITY),
            ));
            grown.push_str(&self.0);
            // The old buffer is zeroized as it drops here.
            self.0 = grown;
        }
        self.0.push_str(s);
    }

    /// Append one character.
    pub(crate) fn push(&mut self, c: char) {
        let mut utf8 = [0u8; 4];
        self.push_str(c.encode_utf8(&mut utf8));
        utf8.zeroize();
    }

    /// Remove the last character. Its bytes stay in the spare capacity until
    /// the buffer is cleared or dropped, both of which wipe it.
    pub(crate) fn pop(&mut self) {
        self.0.pop();
    }

    /// Wipe the contents.
    pub(crate) fn clear(&mut self) {
        self.0.zeroize();
    }

    /// Length in bytes.
    /// Characters typed, for the masked display — not bytes, so a
    /// non-ASCII passphrase shows one `*` per character (#578).
    pub(crate) fn len(&self) -> usize {
        self.0.chars().count()
    }

    /// The text typed so far.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    /// Hand over the passphrase as a secret and wipe the buffer.
    pub(crate) fn take(&mut self) -> SecretString {
        let secret = SecretString::new(self.0.as_str().into());
        self.clear();
        secret
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn grows_edits_and_hands_over() {
        let mut buf = SecretBuffer::default();
        for c in "correct horse battery staple".chars() {
            buf.push(c);
        }
        buf.push_str(&"x".repeat(300));
        buf.pop();
        assert_eq!(buf.len(), 28 + 299);
        let secret = buf.take();
        assert!(secret.expose_secret().starts_with("correct horse"));
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.as_str(), "");
    }
}
