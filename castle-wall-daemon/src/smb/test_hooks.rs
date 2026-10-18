//! Compiled only with smb-test-hooks; never a production configuration switch.
/// Pause through an injected test callback; the marker accompanies every hook.
#[inline(never)]
pub fn smb_test_hook_pause(pause: impl FnOnce(&str)) {
    pause("SMB_TEST_HOOK_MARKER_7f3c");
}
