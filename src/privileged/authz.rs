//! macOS Authorization Services gate for configuration-changing connection
//! operations (`AddConnection`/`RemoveConnection`/an elevating
//! `SetConnectionMode`). See the design plan's authorization section for the
//! full rationale: mere `wgd`-group membership must not be enough to
//! introduce a config whose `PreUp`/`PostUp`/etc. hooks the daemon will later
//! execute as root, so those operations additionally require proof of real
//! admin authentication (password or Touch ID), not just peer-uid ownership.
//!
//! Two-phase protocol (see `dispatch.rs`'s callers of this module):
//!   1. Client sends the request with no `auth_external_form`.
//!   2. If the daemon determines this is a real change (not a no-op), it
//!      replies with a distinct `AuthRequired` error code.
//!   3. The client calls [`client_authorize`] (in the CLI/`privileged_client`
//!      process, unprivileged) to trigger the OS prompt and obtain an
//!      `AuthorizationExternalForm`, then retries with it attached.
//!   4. The daemon verifies the attached form via [`verify_external_form`]
//!      (non-interactive: it must not itself trigger a second, server-side
//!      prompt) before committing the mutation.
//!
//! The custom right this module authorizes against
//! (`me.pansen.wgd.modify-connection`) is registered in the system
//! authorization database at `wgd launchd install` time and before either
//! privileged transport serves requests (see `launchd.rs`), requiring an
//! admin credential with a 60-second, non-shared
//! lifetime for the client-to-daemon handoff. Verification never opens UI.
//!
//! Links `Security.framework` directly: the privileged daemon is macOS-only
//! throughout (hardcoded `/var/run/wireguard`, `networksetup`, launchd, ...),
//! so this module makes no attempt to compile on other platforms.
use std::ffi::CString;
use std::ptr;

use crate::error::{AppError, Result};

/// Must match the right registered by `launchd::register_authorization_right`.
pub const RIGHT_NAME: &str = "me.pansen.wgd.modify-connection";

// ---- raw Authorization Services FFI ---------------------------------------
//
// Hand-written bindings rather than a `core-foundation`/`security-framework`
// dependency: the surface this module needs is exactly four C functions and
// two fixed-layout structs, stable and unchanged since Mac OS X 10.0, and
// keeping it hand-rolled avoids pulling a large crate into a root daemon for
// four function calls.

type OSStatus = i32;
type AuthorizationRef = *mut std::ffi::c_void;
type AuthorizationFlags = u32;

const ERR_SECURITY_SUCCESS: OSStatus = 0;
const ERR_AUTHORIZATION_INTERACTION_NOT_ALLOWED: OSStatus = -60007;

// Values match Security.framework's Authorization.h exactly (verified
// against the installed SDK header, not from memory: it is easy to get an
// FFI constant backwards and have it silently compile).
const K_AUTHORIZATION_FLAG_DEFAULTS: AuthorizationFlags = 0;
const K_AUTHORIZATION_FLAG_INTERACTION_ALLOWED: AuthorizationFlags = 1 << 0;
const K_AUTHORIZATION_FLAG_EXTEND_RIGHTS: AuthorizationFlags = 1 << 1;
/// Passed to `AuthorizationFree` after a successful server-side verification
/// so the verified rights cannot be replayed for a second, unrelated
/// mutation: this actually destroys the credential in securityd, not just
/// this process's reference to it.
const K_AUTHORIZATION_FLAG_DESTROY_RIGHTS: AuthorizationFlags = 1 << 3;

/// `kAuthorizationExternalFormLength` is fixed at 32 bytes by the OS.
pub const EXTERNAL_FORM_LENGTH: usize = 32;

#[repr(C)]
struct AuthorizationItem {
    name: *const std::os::raw::c_char,
    value_length: usize,
    value: *const std::ffi::c_void,
    flags: u32,
}

#[repr(C)]
struct AuthorizationRights {
    count: u32,
    items: *mut AuthorizationItem,
}

#[repr(C)]
struct AuthorizationExternalFormRaw {
    bytes: [u8; EXTERNAL_FORM_LENGTH],
}

#[link(name = "Security", kind = "framework")]
extern "C" {
    fn AuthorizationCreate(
        rights: *const AuthorizationRights,
        environment: *const std::ffi::c_void,
        flags: AuthorizationFlags,
        authorization: *mut AuthorizationRef,
    ) -> OSStatus;

    fn AuthorizationCopyRights(
        authorization: AuthorizationRef,
        rights: *const AuthorizationRights,
        environment: *const std::ffi::c_void,
        flags: AuthorizationFlags,
        authorized_rights: *mut *mut AuthorizationRights,
    ) -> OSStatus;

    fn AuthorizationMakeExternalForm(
        authorization: AuthorizationRef,
        ext_form: *mut AuthorizationExternalFormRaw,
    ) -> OSStatus;

    fn AuthorizationCreateFromExternalForm(
        ext_form: *const AuthorizationExternalFormRaw,
        authorization: *mut AuthorizationRef,
    ) -> OSStatus;

    fn AuthorizationFree(authorization: AuthorizationRef, flags: AuthorizationFlags) -> OSStatus;

    fn AuthorizationFreeItemSet(rights: *mut AuthorizationRights) -> OSStatus;
}

fn os_status_error(context: &str, status: OSStatus) -> AppError {
    AppError::Auth(format!("{context} failed (OSStatus {status})"))
}

fn verification_error(status: OSStatus) -> AppError {
    if status == ERR_AUTHORIZATION_INTERACTION_NOT_ALLOWED {
        return AppError::Auth(format!(
            "admin authorization could not be verified without another prompt \
             (AuthorizationCopyRights OSStatus {status}); the credential may have expired \
             or the installed authorization rule may be outdated. Retry the command; \
             if this persists after an upgrade, run `wgd launchd reload` to update the rule \
             and restart the privileged daemon"
        ));
    }
    AppError::Auth(format!(
        "supplied authorization token does not grant the required right \
         (AuthorizationCopyRights OSStatus {status})"
    ))
}

fn one_right_set(name: &CString) -> AuthorizationRights {
    // `AuthorizationItem.name` borrows `name`'s buffer; the returned struct
    // must not outlive it. Callers keep `name` alive across the FFI call.
    let item = AuthorizationItem {
        name: name.as_ptr(),
        value_length: 0,
        value: ptr::null(),
        flags: 0,
    };
    // Leaked intentionally for the duration of one FFI call via Box::leak
    // would complicate cleanup; instead the caller constructs this in the
    // same stack frame as the call (see `client_authorize`/`verify_external_form`).
    AuthorizationRights {
        count: 1,
        items: Box::into_raw(Box::new(item)),
    }
}

unsafe fn free_one_right_set(rights: AuthorizationRights) {
    if !rights.items.is_null() {
        drop(Box::from_raw(rights.items));
    }
}

/// A live client-side authorization session, held until the retried request
/// has actually been sent to the daemon. **Must not be dropped before that
/// happens**: `AuthorizationFree` destroys the securityd session the
/// external form's rights live in, so freeing it early makes the daemon's
/// `AuthorizationCreateFromExternalForm` fail with `errAuthorizationInvalidRef`
/// even though the form's bytes are still perfectly well-formed -- this was
/// exactly the failure mode of an earlier version of this function, which
/// freed the ref before returning the form.
pub struct ClientAuthorization {
    auth: AuthorizationRef,
    external_form: Vec<u8>,
}

// `AuthorizationRef` is an opaque handle to securityd state; libSecurity
// itself makes no cross-thread-access guarantees for concurrent use of one
// ref, but nothing here does that -- it is created on one thread, optionally
// moved once to be dropped, never used from two threads at once.
unsafe impl Send for ClientAuthorization {}

impl ClientAuthorization {
    #[must_use]
    pub fn external_form(&self) -> &[u8] {
        &self.external_form
    }
}

impl Drop for ClientAuthorization {
    fn drop(&mut self) {
        unsafe { AuthorizationFree(self.auth, K_AUTHORIZATION_FLAG_DEFAULTS) };
    }
}

/// **Client side** (runs unprivileged, in the CLI process): trigger the
/// standard macOS admin-authentication prompt (password or Touch ID) for
/// [`RIGHT_NAME`] and return a [`ClientAuthorization`] holding both the
/// resulting opaque external form (to attach to the retried request) and the
/// live session it came from. This is the call that actually shows UI.
pub fn client_authorize() -> Result<ClientAuthorization> {
    let name = CString::new(RIGHT_NAME)
        .map_err(|e| AppError::Other(format!("invalid right name: {e}")))?;
    let rights = one_right_set(&name);

    let mut auth: AuthorizationRef = ptr::null_mut();
    let create_status = unsafe {
        AuthorizationCreate(
            ptr::null(),
            ptr::null(),
            K_AUTHORIZATION_FLAG_DEFAULTS,
            &mut auth,
        )
    };
    if create_status != ERR_SECURITY_SUCCESS {
        unsafe { free_one_right_set(rights) };
        return Err(os_status_error("AuthorizationCreate", create_status));
    }

    let mut authorized: *mut AuthorizationRights = ptr::null_mut();
    let copy_status = unsafe {
        AuthorizationCopyRights(
            auth,
            &rights,
            ptr::null(),
            K_AUTHORIZATION_FLAG_EXTEND_RIGHTS | K_AUTHORIZATION_FLAG_INTERACTION_ALLOWED,
            &mut authorized,
        )
    };
    unsafe { free_one_right_set(rights) };
    if !authorized.is_null() {
        unsafe { AuthorizationFreeItemSet(authorized) };
    }
    if copy_status != ERR_SECURITY_SUCCESS {
        unsafe { AuthorizationFree(auth, K_AUTHORIZATION_FLAG_DEFAULTS) };
        return Err(os_status_error(
            "AuthorizationCopyRights (admin prompt)",
            copy_status,
        ));
    }

    let mut ext_form = AuthorizationExternalFormRaw {
        bytes: [0u8; EXTERNAL_FORM_LENGTH],
    };
    let form_status = unsafe { AuthorizationMakeExternalForm(auth, &mut ext_form) };
    if form_status != ERR_SECURITY_SUCCESS {
        unsafe { AuthorizationFree(auth, K_AUTHORIZATION_FLAG_DEFAULTS) };
        return Err(os_status_error(
            "AuthorizationMakeExternalForm",
            form_status,
        ));
    }

    Ok(ClientAuthorization {
        auth,
        external_form: ext_form.bytes.to_vec(),
    })
}

/// **Server side** (runs as root, in the privileged daemon): verify a
/// client-supplied external form actually grants [`RIGHT_NAME`], without
/// triggering a second interactive prompt (the client already completed
/// authentication; if the form doesn't hold the right, this must fail rather
/// than prompt again on the daemon's own, non-interactive session).
/// A sentinel external form that dispatch-level tests use to stand in for a
/// real completed admin authentication, without a live authorization session
/// (which a unit/integration test has no way to provide -- exercising the
/// actual OS prompt is a manual check, see the design plan's Verification
/// section). Only recognized in test builds; production code never sees it
/// because `client_authorize` never produces it.
#[cfg(test)]
pub(crate) const TEST_VALID_EXTERNAL_FORM: [u8; EXTERNAL_FORM_LENGTH] =
    [0xABu8; EXTERNAL_FORM_LENGTH];

pub fn verify_external_form(external_form: &[u8]) -> Result<()> {
    if external_form.len() != EXTERNAL_FORM_LENGTH {
        return Err(AppError::Auth(format!(
            "malformed authorization token (expected {EXTERNAL_FORM_LENGTH} bytes, got {})",
            external_form.len()
        )));
    }
    #[cfg(test)]
    if external_form == TEST_VALID_EXTERNAL_FORM {
        return Ok(());
    }
    let mut ext_form = AuthorizationExternalFormRaw {
        bytes: [0u8; EXTERNAL_FORM_LENGTH],
    };
    ext_form.bytes.copy_from_slice(external_form);

    let mut auth: AuthorizationRef = ptr::null_mut();
    let create_status = unsafe { AuthorizationCreateFromExternalForm(&ext_form, &mut auth) };
    if create_status != ERR_SECURITY_SUCCESS {
        return Err(os_status_error(
            "AuthorizationCreateFromExternalForm",
            create_status,
        ));
    }

    let name = CString::new(RIGHT_NAME)
        .map_err(|e| AppError::Other(format!("invalid right name: {e}")))?;
    let rights = one_right_set(&name);
    let mut authorized: *mut AuthorizationRights = ptr::null_mut();
    // Verify only the credential obtained by the client. The authorization
    // session retains GUI access even in this daemon, so allowing interaction
    // here really can display a second prompt. The installed rule must have
    // a nonzero timeout: `authenticate-admin` expires credentials immediately
    // and caused the historical -60007 failure on this non-interactive path.
    let copy_status = unsafe {
        AuthorizationCopyRights(
            auth,
            &rights,
            ptr::null(),
            K_AUTHORIZATION_FLAG_EXTEND_RIGHTS,
            &mut authorized,
        )
    };
    unsafe { free_one_right_set(rights) };
    if !authorized.is_null() {
        unsafe { AuthorizationFreeItemSet(authorized) };
    }
    // On a successful verification, destroy the rights in securityd (not
    // just this process's reference to them): a client-captured external
    // form must be usable for the one retried request it was minted for,
    // not replayable for a later, unrelated mutation. A failed verification
    // never granted anything new, so a plain free is enough there.
    let free_flags = if copy_status == ERR_SECURITY_SUCCESS {
        K_AUTHORIZATION_FLAG_DESTROY_RIGHTS
    } else {
        K_AUTHORIZATION_FLAG_DEFAULTS
    };
    unsafe { AuthorizationFree(auth, free_flags) };

    if copy_status != ERR_SECURITY_SUCCESS {
        return Err(verification_error(copy_status));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interaction_not_allowed_explains_retry_and_upgrade_recovery() {
        let error = verification_error(ERR_AUTHORIZATION_INTERACTION_NOT_ALLOWED);
        assert!(matches!(error, AppError::Auth(_)));
        let message = error.to_string();
        assert!(message.contains("OSStatus -60007"));
        assert!(message.contains("expired"));
        assert!(message.contains("Retry the command"));
        assert!(message.contains("wgd launchd reload"));
    }

    #[test]
    fn other_verification_failures_keep_their_status_without_upgrade_advice() {
        let message = verification_error(-60005).to_string();
        assert!(message.contains("OSStatus -60005"));
        assert!(!message.contains("wgd launchd reload"));
    }

    #[test]
    fn malformed_external_form_length_is_rejected_before_any_ffi_call() {
        let err = verify_external_form(&[0u8; 4]).unwrap_err();
        assert!(err.to_string().contains("32 bytes"));
    }

    #[test]
    fn all_zero_external_form_is_rejected() {
        // A zeroed buffer is never a form `AuthorizationMakeExternalForm`
        // actually produced; this exercises the FFI round trip end-to-end
        // (real admin-prompt verification needs a live session and is a
        // manual check, not a unit test -- see the plan's Verification section).
        let err = verify_external_form(&[0u8; EXTERNAL_FORM_LENGTH]).unwrap_err();
        assert!(matches!(err, AppError::Auth(_)));
    }

    /// Whether [`RIGHT_NAME`] is registered in the system authorization
    /// database (`register_authorization_right`, run by `launchd install` and
    /// by every privileged daemon start).
    ///
    /// `security authorizationdb read` exits 0 for a defined right and
    /// nonzero (-60005, errAuthorizationDenied) for an undefined one.
    fn wgd_right_is_registered() -> bool {
        std::process::Command::new("/usr/bin/security")
            .args(["authorizationdb", "read", RIGHT_NAME])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }

    #[test]
    fn live_but_unauthenticated_external_form_is_rejected() {
        // This asserts a property of *wgd's own* rule: `authenticate-user`
        // with `shared` false, so holding an authorization session grants
        // nothing on its own. Where the rule isn't installed (a CI runner,
        // a checkout that never ran `launchd install`), the undefined right
        // falls back to the system default rule instead -- which is shared
        // and cached, so an admin credential another process minted moments
        // earlier makes `AuthorizationCopyRights` succeed here. That says
        // nothing about the code under test, so skip rather than assert
        // against whatever the machine's ambient credential state happens to
        // be.
        if !wgd_right_is_registered() {
            eprintln!(
                "skipping {RIGHT_NAME} rejection check: the right is not \
                 registered on this machine (run `sudo wgd launchd install`)"
            );
            return;
        }

        let mut auth = ptr::null_mut();
        assert_eq!(
            unsafe {
                AuthorizationCreate(
                    ptr::null(),
                    ptr::null(),
                    K_AUTHORIZATION_FLAG_DEFAULTS,
                    &mut auth,
                )
            },
            ERR_SECURITY_SUCCESS
        );
        let mut form = AuthorizationExternalFormRaw {
            bytes: [0; EXTERNAL_FORM_LENGTH],
        };
        let status = unsafe { AuthorizationMakeExternalForm(auth, &mut form) };
        let authorization = ClientAuthorization {
            auth,
            external_form: form.bytes.to_vec(),
        };
        assert_eq!(status, ERR_SECURITY_SUCCESS);
        // A real, live session is insufficient without an authenticated
        // admin credential. Verification must reject it without opening UI.
        assert!(matches!(
            verify_external_form(authorization.external_form()),
            Err(AppError::Auth(_))
        ));
    }

    #[test]
    #[ignore = "opens one macOS admin prompt; requires the updated authorization rule installed"]
    fn authenticated_external_form_verifies_once_without_reprompting() {
        let authorization = client_authorize().expect("client authentication");
        verify_external_form(authorization.external_form()).expect("non-interactive verification");
        assert!(matches!(
            verify_external_form(authorization.external_form()),
            Err(AppError::Auth(_))
        ));
    }
}
