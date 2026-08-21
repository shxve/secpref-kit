//! Windows SID helpers.
//!
//! Windows-only module (`#[cfg(windows)]` at the crate root). Provides two
//! primitives library consumers commonly need:
//!
//! - [`machine_id`] — Chromium's Windows device ID: the local machine SID.
//! - [`current_user_trimmed`] — the running process user's account-domain SID.
//! - [`lookup_by_name`] — resolve a username (local or `DOMAIN\user`) to
//!   the same SID string form.
//!
//! Chromium obtains the computer name, resolves that name with
//! `LookupAccountNameW`, and uses the resulting machine SID. A user's full
//! SID has a final relative identifier (RID); [`current_user_trimmed`] removes
//! that component for callers that explicitly need the account-domain SID.
//!
//! # Safety
//!
//! This module uses Windows API calls that are `unsafe` by definition
//! (raw pointers, handle lifetimes). Every `unsafe` block is scoped to a
//! single API call and paired with proper cleanup (`CloseHandle`,
//! `LocalFree`). No `unsafe` escapes the module boundary.

#![allow(unsafe_code)]

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr;

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_INSUFFICIENT_BUFFER, HANDLE, HLOCAL,
};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{
    GetTokenInformation, LookupAccountNameW, SidTypeUnknown, TokenUser, PSID, TOKEN_QUERY,
    TOKEN_USER,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::Win32::System::WindowsProgramming::GetComputerNameW;

use crate::SecPrefError;

/// Return the current process user's SID as a `S-1-5-21-...`-form string.
///
/// # Errors
///
/// [`SecPrefError::SidLookup`] wrapping the Win32 error code if any of the
/// underlying calls (`OpenProcessToken`, `GetTokenInformation`,
/// `ConvertSidToStringSidW`) fail.
pub fn current_user_trimmed() -> Result<String, SecPrefError> {
    // SAFETY: every raw pointer is either checked or points into a Vec
    // owned by this stack frame. Handles are wrapped in RAII guards.
    unsafe { current_user_sid_string() }.and_then(|sid| trim_rid(&sid))
}

/// Return Chromium's Windows device ID (the local machine SID).
///
/// This mirrors Chromium's `GetDeterministicMachineSpecificId` implementation:
/// resolve the computer name through `LookupAccountNameW` and stringify the
/// resulting SID.
pub fn machine_id() -> Result<String, SecPrefError> {
    // Windows computer names are at most 63 characters; leave ample room for
    // the terminating NUL and future platform changes.
    let mut buffer = vec![0u16; 256];
    let mut length = u32::try_from(buffer.len()).expect("fixed buffer fits u32");
    // SAFETY: buffer is writable for `length` UTF-16 code units.
    if unsafe { GetComputerNameW(buffer.as_mut_ptr(), &raw mut length) } == 0 {
        return Err(last_error("GetComputerNameW"));
    }
    let name = String::from_utf16_lossy(&buffer[..length as usize]);
    lookup_by_name(&name)
}

/// Look up a user's SID by name.
///
/// Accepts local names (e.g. `alice`) and domain-qualified forms
/// (e.g. `CORP\alice`). Returns the same `S-1-5-21-...`-form string as
/// [`current_user_trimmed`].
///
/// # Errors
///
/// [`SecPrefError::SidLookup`] if `LookupAccountNameW` fails (unknown
/// user, insufficient permissions, malformed name).
pub fn lookup_by_name(user: &str) -> Result<String, SecPrefError> {
    // SAFETY: user_wide is null-terminated and owned by this stack frame.
    unsafe { lookup_sid_string(user) }
}

// --------------------- internal impl (all unsafe) ---------------------

unsafe fn current_user_sid_string() -> Result<String, SecPrefError> {
    let process = GetCurrentProcess();
    let mut token: HANDLE = ptr::null_mut();
    if OpenProcessToken(process, TOKEN_QUERY, &raw mut token) == 0 {
        return Err(last_error("OpenProcessToken"));
    }
    let _guard = HandleGuard(token);

    // First call: query the required buffer size. Expected to fail with
    // ERROR_INSUFFICIENT_BUFFER — anything else is a real error.
    let mut needed: u32 = 0;
    GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &raw mut needed);
    if GetLastError() != ERROR_INSUFFICIENT_BUFFER {
        return Err(last_error("GetTokenInformation size"));
    }

    // Use pointer-sized storage so casting the buffer to TOKEN_USER preserves
    // the alignment required by the Win32 structure.
    let word_size = std::mem::size_of::<usize>();
    let word_count = (needed as usize).div_ceil(word_size);
    let mut buf = vec![0usize; word_count];
    if GetTokenInformation(
        token,
        TokenUser,
        buf.as_mut_ptr().cast(),
        needed,
        &raw mut needed,
    ) == 0
    {
        return Err(last_error("GetTokenInformation"));
    }

    // TOKEN_USER's first field is a SID_AND_ATTRIBUTES with a PSID.
    let token_user = buf.as_ptr().cast::<TOKEN_USER>();
    sid_to_string((*token_user).User.Sid)
}

fn trim_rid(sid: &str) -> Result<String, SecPrefError> {
    let (domain_sid, rid) = sid.rsplit_once('-').ok_or_else(|| {
        SecPrefError::SidLookup(format!("cannot remove RID from malformed SID `{sid}`"))
    })?;
    if rid.parse::<u32>().is_err() || !domain_sid.starts_with("S-1-") {
        return Err(SecPrefError::SidLookup(format!(
            "cannot remove RID from malformed SID `{sid}`"
        )));
    }
    Ok(domain_sid.to_owned())
}

unsafe fn lookup_sid_string(user: &str) -> Result<String, SecPrefError> {
    let mut user_wide: Vec<u16> = OsStr::new(user).encode_wide().collect();
    user_wide.push(0);

    let mut sid_size: u32 = 0;
    let mut domain_size: u32 = 0;
    let mut sid_use: i32 = SidTypeUnknown;

    LookupAccountNameW(
        ptr::null(),
        user_wide.as_ptr(),
        ptr::null_mut(),
        &raw mut sid_size,
        ptr::null_mut(),
        &raw mut domain_size,
        &raw mut sid_use,
    );
    if GetLastError() != ERROR_INSUFFICIENT_BUFFER {
        return Err(last_error("LookupAccountNameW size"));
    }

    let mut sid_buf = vec![0u8; sid_size as usize];
    let mut domain_buf = vec![0u16; domain_size as usize];

    if LookupAccountNameW(
        ptr::null(),
        user_wide.as_ptr(),
        sid_buf.as_mut_ptr().cast(),
        &raw mut sid_size,
        domain_buf.as_mut_ptr(),
        &raw mut domain_size,
        &raw mut sid_use,
    ) == 0
    {
        return Err(last_error("LookupAccountNameW"));
    }

    sid_to_string(sid_buf.as_ptr().cast::<core::ffi::c_void>().cast_mut())
}

unsafe fn sid_to_string(sid: PSID) -> Result<String, SecPrefError> {
    let mut wide_ptr: *mut u16 = ptr::null_mut();
    if ConvertSidToStringSidW(sid, &raw mut wide_ptr) == 0 {
        return Err(last_error("ConvertSidToStringSidW"));
    }
    let s = wide_to_string(wide_ptr);
    LocalFree(wide_ptr as HLOCAL);
    Ok(s)
}

unsafe fn wide_to_string(ptr: *const u16) -> String {
    let mut len = 0;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    let slice = std::slice::from_raw_parts(ptr, len);
    String::from_utf16_lossy(slice)
}

struct HandleGuard(HANDLE);
impl Drop for HandleGuard {
    fn drop(&mut self) {
        // SAFETY: guard owns this handle and drops only once.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

fn last_error(context: &'static str) -> SecPrefError {
    // SAFETY: GetLastError is safe to call from any thread; only reads a
    // TLS slot.
    let code = unsafe { GetLastError() };
    SecPrefError::SidLookup(format!("{context}: WinAPI error 0x{code:08x}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_user_returns_sid_shape() {
        // Runs on Windows CI; on a workstation this pulls the running
        // user's real SID. We only check the shape, not the exact value.
        let sid = current_user_trimmed().expect("current_user_trimmed");
        assert!(sid.starts_with("S-1-"), "unexpected SID shape: {sid}");
        // Typical user account: S-1-5-21-...-<RID>
        assert!(sid.matches('-').count() >= 3, "SID looks too short: {sid}");
    }

    #[test]
    fn trim_rid_removes_only_the_final_component() {
        assert_eq!(
            trim_rid("S-1-5-21-111-222-333-1001").unwrap(),
            "S-1-5-21-111-222-333"
        );
        assert!(trim_rid("not-a-sid").is_err());
    }

    #[test]
    fn machine_id_returns_sid_shape() {
        let sid = machine_id().expect("machine_id");
        assert!(sid.starts_with("S-1-"), "unexpected SID shape: {sid}");
    }

    #[test]
    fn lookup_missing_user_errors() {
        let err = lookup_by_name("nobody-should-have-this-name-12345")
            .expect_err("lookup should fail for unknown user");
        assert!(matches!(err, SecPrefError::SidLookup(_)));
    }
}
