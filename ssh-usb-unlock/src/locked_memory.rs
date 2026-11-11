use std::ops::{Deref, DerefMut};
use zeroize::Zeroize;

/// Endurece el proceso actual a nivel de kernel:
/// 1. Prohíbe volcados de memoria (RLIMIT_CORE = 0).
/// 2. Bloquea adjuntar debuggers (PT_DENY_ATTACH en macOS / PR_SET_DUMPABLE = 0 en Linux).
pub fn harden_process() {
    unsafe {
        let rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &rlim);

        #[cfg(target_os = "macos")]
        {
            libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0);
        }

        #[cfg(target_os = "linux")]
        {
            libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        }
    }
}

/// Buffer RAII de tamaño fijo bloqueado en RAM física con `mlock` y limpiado con `zeroize` al destruirse.
pub struct LockedBuffer<const N: usize> {
    data: Box<[u8; N]>,
}

impl<const N: usize> LockedBuffer<N> {
    pub fn new() -> Self {
        let mut data = Box::new([0u8; N]);
        unsafe {
            let ptr = data.as_mut_ptr() as *mut libc::c_void;
            libc::mlock(ptr, N);

            #[cfg(target_os = "macos")]
            libc::madvise(ptr, N, libc::MADV_ZERO_WIRED_PAGES);

            #[cfg(target_os = "linux")]
            libc::madvise(ptr, N, libc::MADV_DONTDUMP);
        }
        Self { data }
    }
}

impl<const N: usize> Default for LockedBuffer<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Deref for LockedBuffer<N> {
    type Target = [u8; N];

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<const N: usize> DerefMut for LockedBuffer<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl<const N: usize> Drop for LockedBuffer<N> {
    fn drop(&mut self) {
        self.data.zeroize();
        unsafe {
            let ptr = self.data.as_mut_ptr() as *mut libc::c_void;
            libc::munlock(ptr, N);
        }
    }
}