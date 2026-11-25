use std::ops::{Deref, DerefMut};
use zeroize::Zeroize;

#[cfg(windows)]
mod win_mem {
    use core::ffi::c_void;

    #[link(name = "kernel32")]
    extern "system" {
        pub fn VirtualLock(lp_address: *mut c_void, dw_size: usize) -> i32;
        pub fn VirtualUnlock(lp_address: *mut c_void, dw_size: usize) -> i32;
    }
}

/// Endurece el proceso actual a nivel de kernel:
/// - Unix: prohíbe volcados de memoria (`RLIMIT_CORE = 0`) y bloquea debuggers
///   (`PT_DENY_ATTACH` en macOS / `PR_SET_DUMPABLE = 0` en Linux).
/// - Windows: no-op (los volcados no están activos por defecto en procesos de usuario).
pub fn harden_process() {
    #[cfg(unix)]
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

/// Buffer RAII de tamaño fijo bloqueado en RAM física (`mlock` en Unix / `VirtualLock` en Windows)
/// y limpiado con `zeroize` al destruirse.
pub struct LockedBuffer<const N: usize> {
    data: Box<[u8; N]>,
}

impl<const N: usize> LockedBuffer<N> {
    pub fn new() -> Self {
        let mut data = Box::new([0u8; N]);

        #[cfg(unix)]
        unsafe {
            let ptr = data.as_mut_ptr() as *mut libc::c_void;
            libc::mlock(ptr, N);

            #[cfg(target_os = "macos")]
            libc::madvise(ptr, N, libc::MADV_ZERO_WIRED_PAGES);

            #[cfg(target_os = "linux")]
            libc::madvise(ptr, N, libc::MADV_DONTDUMP);
        }

        #[cfg(windows)]
        unsafe {
            let ptr = data.as_mut_ptr() as *mut core::ffi::c_void;
            win_mem::VirtualLock(ptr, N);
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

        #[cfg(unix)]
        unsafe {
            let ptr = self.data.as_mut_ptr() as *mut libc::c_void;
            libc::munlock(ptr, N);
        }

        #[cfg(windows)]
        unsafe {
            let ptr = self.data.as_mut_ptr() as *mut core::ffi::c_void;
            win_mem::VirtualUnlock(ptr, N);
        }
    }
}
