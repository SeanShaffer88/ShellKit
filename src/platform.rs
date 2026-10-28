//! Platform layer: the only place Windows APIs are touched.
//! On non-Windows targets `backend()` returns ERR_NOT_SUPPORTED so
//! the pure logic (planning + backup inversion) and the FFI
//! contract stay testable anywhere.
//!
//! Every extern block MUST carry #[link(name = "...")] naming its
//! import library. Without it the build fails at LINK time with
//! LNK2019 — check and clippy cannot catch it; CI's real build can.
//!
//! The Windows backend writes HKEY_CURRENT_USER only. Key paths
//! arriving here have already been validated by the core to live
//! under `Software\Classes`.

use crate::{RegistryBackend, ShResult};

/// Construct the real registry backend. On non-Windows there is
/// none: apply/restore are documented NOT_SUPPORTED there.
#[cfg(windows)]
pub fn backend() -> ShResult<Box<dyn RegistryBackend>> {
    Ok(Box::new(win::WinRegistry))
}

#[cfg(not(windows))]
pub fn backend() -> ShResult<Box<dyn RegistryBackend>> {
    Err((
        crate::ERR_NOT_SUPPORTED,
        "applying a plan is only available on Windows (planning and backup inversion work on every platform)"
            .to_string(),
    ))
}

/// Replace an app's custom jump list with `tasks` (Windows
/// only, via the DestinationList COM surface in `com`).
#[cfg(windows)]
pub fn apply_jump_list(app_id: &str, tasks: &[crate::JumpTask]) -> ShResult<()> {
    com::apply_jump_list(app_id, tasks)
}

#[cfg(not(windows))]
pub fn apply_jump_list(_app_id: &str, _tasks: &[crate::JumpTask]) -> ShResult<()> {
    Err((
        crate::ERR_NOT_SUPPORTED,
        "applying a jump list is only available on Windows (planning works on every platform)"
            .to_string(),
    ))
}

/// Clear an app's custom jump list entirely — this is what
/// restoring a jump-list backup means (Windows only).
#[cfg(windows)]
pub fn delete_jump_list(app_id: &str) -> ShResult<()> {
    com::delete_jump_list(app_id)
}

#[cfg(not(windows))]
pub fn delete_jump_list(_app_id: &str) -> ShResult<()> {
    Err((
        crate::ERR_NOT_SUPPORTED,
        "clearing a jump list (restoring a jump-list backup) is only available on Windows"
            .to_string(),
    ))
}

#[cfg(windows)]
mod win {
    use super::RegistryBackend;
    use crate::{ShResult, SubtreeSnapshot, ERR_ACCESS_DENIED, ERR_NOT_FOUND, ERR_PLATFORM};
    use std::ffi::c_void;

    type Hkey = *mut c_void;
    type Lstatus = i32;

    const HKEY_CURRENT_USER: usize = 0x8000_0001;
    const KEY_QUERY_VALUE: u32 = 0x0001;
    const KEY_SET_VALUE: u32 = 0x0002;
    const KEY_ENUMERATE_SUB_KEYS: u32 = 0x0008;
    const KEY_READ: u32 = 0x20019; // STANDARD_RIGHTS_READ | QUERY_VALUE | ENUMERATE_SUB_KEYS | NOTIFY
    const KEY_WRITE: u32 = 0x20006; // STANDARD_RIGHTS_WRITE | SET_VALUE | CREATE_SUB_KEY
    const REG_SZ: u32 = 1;
    const REG_EXPAND_SZ: u32 = 2;
    const ERROR_SUCCESS: i32 = 0;
    const ERROR_FILE_NOT_FOUND: i32 = 2;
    const ERROR_ACCESS_DENIED: i32 = 5;
    const ERROR_MORE_DATA: i32 = 234;
    const ERROR_NO_MORE_ITEMS: i32 = 259;

    /// Bounds for subtree snapshots: registration subtrees are
    /// small; the caps keep a hostile or corrupt tree from turning
    /// a snapshot into unbounded work.
    const MAX_DEPTH: usize = 32;
    const MAX_KEYS: usize = 4096;

    #[link(name = "advapi32")]
    extern "system" {
        fn RegCreateKeyExW(
            hkey: Hkey,
            subkey: *const u16,
            reserved: u32,
            class: *const u16,
            options: u32,
            sam_desired: u32,
            security_attributes: *const c_void,
            result: *mut Hkey,
            disposition: *mut u32,
        ) -> Lstatus;
        fn RegOpenKeyExW(
            hkey: Hkey,
            subkey: *const u16,
            options: u32,
            sam_desired: u32,
            result: *mut Hkey,
        ) -> Lstatus;
        fn RegCloseKey(hkey: Hkey) -> Lstatus;
        fn RegSetValueExW(
            hkey: Hkey,
            value_name: *const u16,
            reserved: u32,
            value_type: u32,
            data: *const u8,
            data_len: u32,
        ) -> Lstatus;
        fn RegEnumValueW(
            hkey: Hkey,
            index: u32,
            value_name: *mut u16,
            value_name_len: *mut u32,
            reserved: *mut u32,
            value_type: *mut u32,
            data: *mut u8,
            data_len: *mut u32,
        ) -> Lstatus;
        fn RegEnumKeyExW(
            hkey: Hkey,
            index: u32,
            name: *mut u16,
            name_len: *mut u32,
            reserved: *mut u32,
            class: *mut u16,
            class_len: *mut u32,
            last_write: *mut c_void,
        ) -> Lstatus;
        fn RegDeleteTreeW(hkey: Hkey, subkey: *const u16) -> Lstatus;
        fn RegDeleteValueW(hkey: Hkey, value_name: *const u16) -> Lstatus;
    }

    fn hkcu() -> Hkey {
        HKEY_CURRENT_USER as Hkey
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Value-name pointer: the registry's (Default) value is
    /// addressed with a NULL name, not an empty string.
    fn name_ptr(name: &str, buf: &mut Vec<u16>) -> *const u16 {
        if name.is_empty() {
            std::ptr::null()
        } else {
            *buf = wide(name);
            buf.as_ptr()
        }
    }

    fn reg_err(rc: Lstatus, what: &str) -> (i32, String) {
        match rc {
            ERROR_ACCESS_DENIED => (
                ERR_ACCESS_DENIED,
                format!("{what}: access denied (Windows error 5)"),
            ),
            ERROR_FILE_NOT_FOUND => (
                ERR_NOT_FOUND,
                format!("{what}: key or value not found (Windows error 2)"),
            ),
            _ => (ERR_PLATFORM, format!("{what}: Windows error {rc}")),
        }
    }

    /// An opened key that closes itself.
    struct OpenKey(Hkey);
    impl Drop for OpenKey {
        fn drop(&mut self) {
            unsafe {
                RegCloseKey(self.0);
            }
        }
    }

    fn create_key_handle(key: &str, sam: u32) -> ShResult<OpenKey> {
        let w = wide(key);
        let mut h: Hkey = std::ptr::null_mut();
        let rc = unsafe {
            RegCreateKeyExW(
                hkcu(),
                w.as_ptr(),
                0,
                std::ptr::null(),
                0,
                sam,
                std::ptr::null(),
                &mut h,
                std::ptr::null_mut(),
            )
        };
        if rc != ERROR_SUCCESS {
            return Err(reg_err(rc, &format!("create/open key \"{key}\"")));
        }
        Ok(OpenKey(h))
    }

    /// Open an existing key; Ok(None) when it does not exist.
    fn open_key_handle(key: &str, sam: u32) -> ShResult<Option<OpenKey>> {
        let w = wide(key);
        let mut h: Hkey = std::ptr::null_mut();
        let rc = unsafe { RegOpenKeyExW(hkcu(), w.as_ptr(), 0, sam, &mut h) };
        match rc {
            ERROR_SUCCESS => Ok(Some(OpenKey(h))),
            ERROR_FILE_NOT_FOUND => Ok(None),
            _ => Err(reg_err(rc, &format!("open key \"{key}\""))),
        }
    }

    fn utf16_lossy_trim_nul(units: &[u16]) -> String {
        let end = units
            .iter()
            .rposition(|&u| u != 0)
            .map(|i| i + 1)
            .unwrap_or(0);
        String::from_utf16_lossy(&units[..end])
    }

    /// Read all string values of one already-open key.
    fn read_values(h: Hkey, key_path: &str) -> ShResult<Vec<(String, String, bool)>> {
        let mut out = Vec::new();
        let mut index: u32 = 0;
        loop {
            let mut name_buf = vec![0u16; 2048];
            let mut name_len = name_buf.len() as u32;
            let mut value_type: u32 = 0;
            let mut data_buf = vec![0u8; 8192];
            let mut data_len = data_buf.len() as u32;
            let mut rc = unsafe {
                RegEnumValueW(
                    h,
                    index,
                    name_buf.as_mut_ptr(),
                    &mut name_len,
                    std::ptr::null_mut(),
                    &mut value_type,
                    data_buf.as_mut_ptr(),
                    &mut data_len,
                )
            };
            if rc == ERROR_MORE_DATA {
                // Grow to the reported sizes and retry this index.
                name_buf = vec![0u16; (name_len as usize) + 1];
                name_len = name_buf.len() as u32;
                data_buf = vec![0u8; data_len as usize];
                let mut dl = data_buf.len() as u32;
                rc = unsafe {
                    RegEnumValueW(
                        h,
                        index,
                        name_buf.as_mut_ptr(),
                        &mut name_len,
                        std::ptr::null_mut(),
                        &mut value_type,
                        data_buf.as_mut_ptr(),
                        &mut dl,
                    )
                };
                data_len = dl;
            }
            if rc == ERROR_NO_MORE_ITEMS {
                break;
            }
            if rc != ERROR_SUCCESS {
                return Err(reg_err(rc, &format!("enumerate values of \"{key_path}\"")));
            }
            let expand = match value_type {
                REG_SZ => false,
                REG_EXPAND_SZ => true,
                other => {
                    return Err((
                        ERR_PLATFORM,
                        format!(
                            "key \"{key_path}\" contains a value of registry type {other}, which a ShellKit backup cannot represent; refusing to proceed rather than back it up lossily"
                        ),
                    ))
                }
            };
            let name = utf16_lossy_trim_nul(&name_buf[..name_len as usize]);
            let units: Vec<u16> = data_buf[..data_len as usize]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            let data = utf16_lossy_trim_nul(&units);
            out.push((name, data, expand));
            index += 1;
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(out)
    }

    fn snapshot_into(key: &str, depth: usize, out: &mut SubtreeSnapshot) -> ShResult<()> {
        if depth > MAX_DEPTH {
            return Err((
                ERR_PLATFORM,
                format!(
                    "key \"{key}\": subtree deeper than {MAX_DEPTH} levels; refusing to snapshot"
                ),
            ));
        }
        if out.len() >= MAX_KEYS {
            return Err((
                ERR_PLATFORM,
                format!("subtree at \"{key}\" exceeds {MAX_KEYS} keys; refusing to snapshot"),
            ));
        }
        let handle = match open_key_handle(key, KEY_READ | KEY_ENUMERATE_SUB_KEYS)? {
            Some(h) => h,
            None => return Ok(()),
        };
        let values = read_values(handle.0, key)?;
        out.push((key.to_string(), values));
        // Enumerate subkey names, then recurse (parents first:
        // this key was pushed before any descendant).
        let mut names = Vec::new();
        let mut index: u32 = 0;
        loop {
            let mut buf = vec![0u16; 256];
            let mut len = buf.len() as u32;
            let rc = unsafe {
                RegEnumKeyExW(
                    handle.0,
                    index,
                    buf.as_mut_ptr(),
                    &mut len,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            if rc == ERROR_NO_MORE_ITEMS {
                break;
            }
            if rc != ERROR_SUCCESS {
                return Err(reg_err(rc, &format!("enumerate subkeys of \"{key}\"")));
            }
            names.push(utf16_lossy_trim_nul(&buf[..len as usize]));
            index += 1;
        }
        drop(handle);
        for name in names {
            snapshot_into(&format!("{key}\\{name}"), depth + 1, out)?;
        }
        Ok(())
    }

    pub struct WinRegistry;

    impl RegistryBackend for WinRegistry {
        fn snapshot(&mut self, key: &str) -> ShResult<Option<SubtreeSnapshot>> {
            if open_key_handle(key, KEY_QUERY_VALUE)?.is_none() {
                return Ok(None);
            }
            let mut out = Vec::new();
            snapshot_into(key, 0, &mut out)?;
            if out.is_empty() {
                // The key existed at the existence check but the
                // walk found nothing (deleted in between): report
                // the key itself with no values rather than None,
                // so inversion still protects it.
                out.push((key.to_string(), Vec::new()));
            }
            Ok(Some(out))
        }

        fn create_key(&mut self, key: &str) -> ShResult<()> {
            let _ = create_key_handle(key, KEY_WRITE)?;
            Ok(())
        }

        fn set_string(&mut self, key: &str, name: &str, value: &str, expand: bool) -> ShResult<()> {
            let handle = create_key_handle(key, KEY_WRITE | KEY_QUERY_VALUE)?;
            let mut name_buf = Vec::new();
            let np = name_ptr(name, &mut name_buf);
            let data = wide(value);
            let rc = unsafe {
                RegSetValueExW(
                    handle.0,
                    np,
                    0,
                    if expand { REG_EXPAND_SZ } else { REG_SZ },
                    data.as_ptr() as *const u8,
                    (data.len() * 2) as u32,
                )
            };
            if rc != ERROR_SUCCESS {
                return Err(reg_err(rc, &format!("set value \"{name}\" in \"{key}\"")));
            }
            Ok(())
        }

        fn delete_key(&mut self, key: &str) -> ShResult<()> {
            let w = wide(key);
            let rc = unsafe { RegDeleteTreeW(hkcu(), w.as_ptr()) };
            match rc {
                ERROR_SUCCESS | ERROR_FILE_NOT_FOUND => Ok(()),
                _ => Err(reg_err(rc, &format!("delete key \"{key}\""))),
            }
        }

        fn delete_value(&mut self, key: &str, name: &str) -> ShResult<()> {
            let handle = match open_key_handle(key, KEY_SET_VALUE)? {
                Some(h) => h,
                None => return Ok(()),
            };
            let mut name_buf = Vec::new();
            let np = name_ptr(name, &mut name_buf);
            let rc = unsafe { RegDeleteValueW(handle.0, np) };
            match rc {
                ERROR_SUCCESS | ERROR_FILE_NOT_FOUND => Ok(()),
                _ => Err(reg_err(
                    rc,
                    &format!("delete value \"{name}\" in \"{key}\""),
                )),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Jump lists: the DestinationList COM surface.
//
// Everything below was checked against the `windows` crate's
// generated bindings before it was written — vtable layouts are
// ABI, and a wrong slot calls the wrong method silently:
//
// - ICustomDestinationList vtable (windows crate docs,
//   Windows::Win32::UI::Shell, ICustomDestinationList_Vtbl):
//   after IUnknown — SetAppID, BeginList, AppendCategory,
//   AppendKnownCategory, AddUserTasks, CommitList,
//   GetRemovedDestinations, DeleteList, AbortList. Nine
//   methods; there is NO AddCustomCategory in this interface,
//   and CommitList comes right after AddUserTasks.
// - IShellLinkW vtable (same source, IShellLinkW_Vtbl):
//   GetPath, GetIDList, SetIDList, GetDescription,
//   SetDescription, GetWorkingDirectory, SetWorkingDirectory,
//   GetArguments, SetArguments, GetHotkey, SetHotkey,
//   GetShowCmd, SetShowCmd, GetIconLocation, SetIconLocation,
//   SetRelativePath, Resolve, SetPath.
// - IPropertyStore vtable (windows crate docs,
//   Windows::Win32::UI::Shell::PropertiesSystem,
//   IPropertyStore_Vtbl): GetCount, GetAt, GetValue, SetValue,
//   Commit.
// - IObjectArray / IObjectCollection (objectarray.h): the
//   array is GetCount, GetAt; the collection extends it with
//   AddObject, AddFromArray, RemoveObjectAt, Clear.
// - GUIDs are the SDK values (shobjidl_core.h / objbase.h /
//   propsys.h, as projected by the windows crate):
//   CLSID_DestinationList, CLSID_ShellLink,
//   CLSID_EnumerableObjectCollection and the interface IIDs.
// - PKEY_Title is {F29F85E0-4FF9-1068-AB91-08002B27B3D9}:2
//   (propkey.h; windows crate PropertiesSystem::PKEY_Title),
//   and a task title is a VT_LPWSTR (31) PROPVARIANT.
//
// ole32's entry points are resolved dynamically
// (LoadLibraryW/GetProcAddress) so this module adds NO import
// library dependency. kernel32 itself is declared with the
// house #[link] rule like every other extern block.
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod com {
    use crate::{JumpTask, ShResult, ERR_PLATFORM};
    use std::ffi::c_void;

    type HResult = i32;

    const S_OK: HResult = 0;
    const RPC_E_CHANGED_MODE: HResult = 0x8001_0106u32 as i32;
    const COINIT_APARTMENTTHREADED: u32 = 0x2;
    const CLSCTX_INPROC_SERVER: u32 = 0x1;
    const VT_LPWSTR: u16 = 31;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Guid {
        data1: u32,
        data2: u16,
        data3: u16,
        data4: [u8; 8],
    }

    const CLSID_DESTINATION_LIST: Guid = Guid {
        data1: 0x77f1_0cf0,
        data2: 0x3db5,
        data3: 0x4966,
        data4: [0xb5, 0x20, 0xb7, 0xc5, 0x4f, 0xd3, 0x5e, 0xd6],
    };
    const IID_CUSTOM_DESTINATION_LIST: Guid = Guid {
        data1: 0x6332_debf,
        data2: 0x87b5,
        data3: 0x4670,
        data4: [0x90, 0xc0, 0x5e, 0x57, 0xb4, 0x08, 0xa4, 0x9e],
    };
    const CLSID_SHELL_LINK: Guid = Guid {
        data1: 0x0002_1401,
        data2: 0x0000,
        data3: 0x0000,
        data4: [0xc0, 0, 0, 0, 0, 0, 0, 0x46],
    };
    const IID_SHELL_LINK_W: Guid = Guid {
        data1: 0x0002_14f9,
        data2: 0x0000,
        data3: 0x0000,
        data4: [0xc0, 0, 0, 0, 0, 0, 0, 0x46],
    };
    const CLSID_ENUMERABLE_OBJECT_COLLECTION: Guid = Guid {
        data1: 0x2d34_68c1,
        data2: 0x36a7,
        data3: 0x43b6,
        data4: [0xac, 0x24, 0xd3, 0xf0, 0x2f, 0xd9, 0x60, 0x7a],
    };
    const IID_OBJECT_COLLECTION: Guid = Guid {
        data1: 0x5632_b1a4,
        data2: 0xe38a,
        data3: 0x400a,
        data4: [0x92, 0x8a, 0xd4, 0xcd, 0x63, 0x23, 0x02, 0x95],
    };
    const IID_OBJECT_ARRAY: Guid = Guid {
        data1: 0x92ca_9dcd,
        data2: 0x5622,
        data3: 0x4bba,
        data4: [0xa8, 0x05, 0x5e, 0x9f, 0x54, 0x1b, 0xd8, 0xc9],
    };
    const IID_PROPERTY_STORE: Guid = Guid {
        data1: 0x886d_8eeb,
        data2: 0x8cf2,
        data3: 0x4446,
        data4: [0x8d, 0x02, 0xcd, 0xba, 0x1d, 0xbd, 0xcf, 0x99],
    };

    #[repr(C)]
    struct PropertyKey {
        fmtid: Guid,
        pid: u32,
    }

    /// System.Title — the property a jump-list task's display
    /// text lives in.
    const PKEY_TITLE: PropertyKey = PropertyKey {
        fmtid: Guid {
            data1: 0xf29f_85e0,
            data2: 0x4ff9,
            data3: 0x1068,
            data4: [0xab, 0x91, 0x08, 0x00, 0x2b, 0x27, 0xb3, 0xd9],
        },
        pid: 2,
    };

    /// PROPVARIANT with the layout of propidl.h: the VARTYPE,
    /// three reserved words, then the union (the string pointer
    /// for VT_LPWSTR). The trailing `usize` pads the struct to
    /// the real PROPVARIANT size on both 32- and 64-bit (the
    /// union's largest member, BLOB, is two words).
    #[repr(C)]
    struct PropVariant {
        vt: u16,
        reserved1: u16,
        reserved2: u16,
        reserved3: u16,
        pwsz_val: *const u16,
        _pad: usize,
    }

    // Vtable slots (IUnknown occupies 0..=2 everywhere).
    const SLOT_QUERY_INTERFACE: usize = 0;
    const SLOT_RELEASE: usize = 2;
    // ICustomDestinationList
    const CDL_SET_APP_ID: usize = 3;
    const CDL_BEGIN_LIST: usize = 4;
    const CDL_ADD_USER_TASKS: usize = 7;
    const CDL_COMMIT_LIST: usize = 8;
    const CDL_DELETE_LIST: usize = 10;
    const CDL_ABORT_LIST: usize = 11;
    // IShellLinkW
    const SL_SET_DESCRIPTION: usize = 7;
    const SL_SET_ARGUMENTS: usize = 11;
    const SL_SET_ICON_LOCATION: usize = 17;
    const SL_SET_PATH: usize = 20;
    // IObjectCollection (IObjectArray's GetCount/GetAt are 3/4)
    const OC_ADD_OBJECT: usize = 5;
    // IPropertyStore
    const PS_SET_VALUE: usize = 6;
    const PS_COMMIT: usize = 7;

    #[link(name = "kernel32")]
    extern "system" {
        fn LoadLibraryW(name: *const u16) -> *mut c_void;
        fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
    }

    type CoInitializeExFn =
        unsafe extern "system" fn(reserved: *mut c_void, co_init: u32) -> HResult;
    type CoUninitializeFn = unsafe extern "system" fn();
    type CoCreateInstanceFn = unsafe extern "system" fn(
        rclsid: *const Guid,
        outer: *mut c_void,
        cls_context: u32,
        riid: *const Guid,
        result: *mut *mut c_void,
    ) -> HResult;

    struct Ole32 {
        co_initialize_ex: CoInitializeExFn,
        co_uninitialize: CoUninitializeFn,
        co_create_instance: CoCreateInstanceFn,
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn hr_err(what: &str, hr: HResult) -> (i32, String) {
        (
            ERR_PLATFORM,
            format!("{what} failed: HRESULT 0x{:08X}", hr as u32),
        )
    }

    fn check(what: &str, hr: HResult) -> ShResult<()> {
        if hr == S_OK {
            Ok(())
        } else {
            Err(hr_err(what, hr))
        }
    }

    fn load_ole32() -> ShResult<Ole32> {
        let name = wide("ole32.dll");
        let module = unsafe { LoadLibraryW(name.as_ptr()) };
        if module.is_null() {
            return Err((
                ERR_PLATFORM,
                "could not load ole32.dll to reach the COM runtime".to_string(),
            ));
        }
        // The module stays loaded for the process lifetime by
        // design: the resolved pointers must outlive every call
        // below, and ole32 is a system DLL that is always safe
        // to keep mapped.
        unsafe fn resolve<T>(module: *mut c_void, proc: &[u8]) -> ShResult<T> {
            let p = unsafe { GetProcAddress(module, proc.as_ptr()) };
            if p.is_null() {
                return Err((
                    ERR_PLATFORM,
                    format!(
                        "ole32.dll has no {} entry point",
                        String::from_utf8_lossy(&proc[..proc.len() - 1])
                    ),
                ));
            }
            Ok(unsafe { std::mem::transmute_copy(&p) })
        }
        let co_initialize_ex: CoInitializeExFn = unsafe { resolve(module, b"CoInitializeEx\0") }?;
        let co_uninitialize: CoUninitializeFn = unsafe { resolve(module, b"CoUninitialize\0") }?;
        let co_create_instance: CoCreateInstanceFn =
            unsafe { resolve(module, b"CoCreateInstance\0") }?;
        Ok(Ole32 {
            co_initialize_ex,
            co_uninitialize,
            co_create_instance,
        })
    }

    /// A COM apartment for one apply/delete call. When the
    /// calling thread already has an apartment of a DIFFERENT
    /// model, CoInitializeEx reports RPC_E_CHANGED_MODE: COM
    /// calls still work in the existing apartment, so proceed —
    /// but that initialization is not ours, so it is not
    /// balanced with a CoUninitialize on drop.
    struct ComSession {
        ole: Ole32,
        uninit_owed: bool,
    }

    impl ComSession {
        fn new() -> ShResult<ComSession> {
            let ole = load_ole32()?;
            let hr =
                unsafe { (ole.co_initialize_ex)(std::ptr::null_mut(), COINIT_APARTMENTTHREADED) };
            if hr >= 0 {
                // S_OK or S_FALSE: this call initialized (or
                // counted) the apartment; balance it on drop.
                Ok(ComSession {
                    ole,
                    uninit_owed: true,
                })
            } else if hr == RPC_E_CHANGED_MODE {
                Ok(ComSession {
                    ole,
                    uninit_owed: false,
                })
            } else {
                Err(hr_err("CoInitializeEx", hr))
            }
        }

        fn create(&self, clsid: &Guid, iid: &Guid, what: &str) -> ShResult<ComPtr> {
            let mut raw: *mut c_void = std::ptr::null_mut();
            let hr = unsafe {
                (self.ole.co_create_instance)(
                    clsid,
                    std::ptr::null_mut(),
                    CLSCTX_INPROC_SERVER,
                    iid,
                    &mut raw,
                )
            };
            check(&format!("CoCreateInstance({what})"), hr)?;
            if raw.is_null() {
                return Err((
                    ERR_PLATFORM,
                    format!("CoCreateInstance({what}) returned a null interface"),
                ));
            }
            Ok(ComPtr(raw))
        }
    }

    impl Drop for ComSession {
        fn drop(&mut self) {
            if self.uninit_owed {
                unsafe { (self.ole.co_uninitialize)() }
            }
        }
    }

    /// An owned interface pointer: released through its vtable
    /// on drop.
    struct ComPtr(*mut c_void);

    impl Drop for ComPtr {
        fn drop(&mut self) {
            unsafe { release(self.0) }
        }
    }

    unsafe fn vtable(p: *mut c_void) -> *const *const c_void {
        unsafe { *(p as *const *const *const c_void) }
    }

    unsafe fn slot<T>(p: *mut c_void, index: usize) -> T {
        unsafe {
            let entry = *vtable(p).add(index);
            std::mem::transmute_copy(&entry)
        }
    }

    unsafe fn release(p: *mut c_void) {
        if !p.is_null() {
            type ReleaseFn = unsafe extern "system" fn(*mut c_void) -> u32;
            let f: ReleaseFn = unsafe { slot(p, SLOT_RELEASE) };
            unsafe { f(p) };
        }
    }

    unsafe fn query_interface(p: *mut c_void, iid: &Guid, what: &str) -> ShResult<ComPtr> {
        type QueryInterfaceFn =
            unsafe extern "system" fn(*mut c_void, *const Guid, *mut *mut c_void) -> HResult;
        let f: QueryInterfaceFn = unsafe { slot(p, SLOT_QUERY_INTERFACE) };
        let mut raw: *mut c_void = std::ptr::null_mut();
        let hr = unsafe { f(p, iid, &mut raw) };
        check(&format!("QueryInterface({what})"), hr)?;
        if raw.is_null() {
            return Err((
                ERR_PLATFORM,
                format!("QueryInterface({what}) returned a null interface"),
            ));
        }
        Ok(ComPtr(raw))
    }

    // -- ICustomDestinationList calls -------------------------------------

    unsafe fn cdl_set_app_id(list: *mut c_void, app_id: *const u16) -> HResult {
        type Fn = unsafe extern "system" fn(*mut c_void, *const u16) -> HResult;
        let f: Fn = unsafe { slot(list, CDL_SET_APP_ID) };
        unsafe { f(list, app_id) }
    }

    unsafe fn cdl_begin_list(
        list: *mut c_void,
        min_slots: *mut u32,
        removed: *mut *mut c_void,
    ) -> HResult {
        type Fn = unsafe extern "system" fn(
            *mut c_void,
            *mut u32,
            *const Guid,
            *mut *mut c_void,
        ) -> HResult;
        let f: Fn = unsafe { slot(list, CDL_BEGIN_LIST) };
        unsafe { f(list, min_slots, &IID_OBJECT_ARRAY, removed) }
    }

    unsafe fn cdl_add_user_tasks(list: *mut c_void, tasks: *mut c_void) -> HResult {
        type Fn = unsafe extern "system" fn(*mut c_void, *mut c_void) -> HResult;
        let f: Fn = unsafe { slot(list, CDL_ADD_USER_TASKS) };
        unsafe { f(list, tasks) }
    }

    unsafe fn cdl_commit_list(list: *mut c_void) -> HResult {
        type Fn = unsafe extern "system" fn(*mut c_void) -> HResult;
        let f: Fn = unsafe { slot(list, CDL_COMMIT_LIST) };
        unsafe { f(list) }
    }

    unsafe fn cdl_delete_list(list: *mut c_void, app_id: *const u16) -> HResult {
        type Fn = unsafe extern "system" fn(*mut c_void, *const u16) -> HResult;
        let f: Fn = unsafe { slot(list, CDL_DELETE_LIST) };
        unsafe { f(list, app_id) }
    }

    unsafe fn cdl_abort_list(list: *mut c_void) -> HResult {
        type Fn = unsafe extern "system" fn(*mut c_void) -> HResult;
        let f: Fn = unsafe { slot(list, CDL_ABORT_LIST) };
        unsafe { f(list) }
    }

    // -- IShellLinkW calls -------------------------------------------------

    unsafe fn sl_set_path(link: *mut c_void, path: *const u16) -> HResult {
        type Fn = unsafe extern "system" fn(*mut c_void, *const u16) -> HResult;
        let f: Fn = unsafe { slot(link, SL_SET_PATH) };
        unsafe { f(link, path) }
    }

    unsafe fn sl_set_arguments(link: *mut c_void, args: *const u16) -> HResult {
        type Fn = unsafe extern "system" fn(*mut c_void, *const u16) -> HResult;
        let f: Fn = unsafe { slot(link, SL_SET_ARGUMENTS) };
        unsafe { f(link, args) }
    }

    unsafe fn sl_set_description(link: *mut c_void, description: *const u16) -> HResult {
        type Fn = unsafe extern "system" fn(*mut c_void, *const u16) -> HResult;
        let f: Fn = unsafe { slot(link, SL_SET_DESCRIPTION) };
        unsafe { f(link, description) }
    }

    unsafe fn sl_set_icon_location(link: *mut c_void, icon: *const u16, index: i32) -> HResult {
        type Fn = unsafe extern "system" fn(*mut c_void, *const u16, i32) -> HResult;
        let f: Fn = unsafe { slot(link, SL_SET_ICON_LOCATION) };
        unsafe { f(link, icon, index) }
    }

    // -- IObjectCollection / IPropertyStore calls ---------------------------

    unsafe fn oc_add_object(collection: *mut c_void, object: *mut c_void) -> HResult {
        type Fn = unsafe extern "system" fn(*mut c_void, *mut c_void) -> HResult;
        let f: Fn = unsafe { slot(collection, OC_ADD_OBJECT) };
        unsafe { f(collection, object) }
    }

    unsafe fn ps_set_value(store: *mut c_void, key: &PropertyKey, value: &PropVariant) -> HResult {
        type Fn = unsafe extern "system" fn(
            *mut c_void,
            *const PropertyKey,
            *const PropVariant,
        ) -> HResult;
        let f: Fn = unsafe { slot(store, PS_SET_VALUE) };
        unsafe { f(store, key, value) }
    }

    unsafe fn ps_commit(store: *mut c_void) -> HResult {
        type Fn = unsafe extern "system" fn(*mut c_void) -> HResult;
        let f: Fn = unsafe { slot(store, PS_COMMIT) };
        unsafe { f(store) }
    }

    /// Build one task's shell link: target, optional arguments /
    /// description / icon, and the title property the taskbar
    /// displays. The title is set through the link's
    /// IPropertyStore as PKEY_Title — without it the task does
    /// not display at all, which is why the planner makes the
    /// title mandatory.
    fn make_task_link(session: &ComSession, task: &JumpTask) -> ShResult<ComPtr> {
        let link = session.create(&CLSID_SHELL_LINK, &IID_SHELL_LINK_W, "IShellLinkW")?;
        let target = wide(&task.target);
        check("IShellLinkW::SetPath", unsafe {
            sl_set_path(link.0, target.as_ptr())
        })?;
        if let Some(args) = &task.args {
            let args = wide(args);
            check("IShellLinkW::SetArguments", unsafe {
                sl_set_arguments(link.0, args.as_ptr())
            })?;
        }
        if let Some(description) = &task.description {
            let description = wide(description);
            check("IShellLinkW::SetDescription", unsafe {
                sl_set_description(link.0, description.as_ptr())
            })?;
        }
        if let Some(icon) = &task.icon {
            let icon = wide(icon);
            check("IShellLinkW::SetIconLocation", unsafe {
                sl_set_icon_location(link.0, icon.as_ptr(), task.icon_index as i32)
            })?;
        }
        let store = unsafe { query_interface(link.0, &IID_PROPERTY_STORE, "IPropertyStore") }?;
        let title = wide(&task.title);
        // IPropertyStore::SetValue copies the PROPVARIANT's
        // contents synchronously (the windows crate binding
        // takes it as a `*const PROPVARIANT`, and Microsoft's
        // own jump-list sample passes a borrowed pwszVal the
        // same way), so the title string is lent, not handed
        // over: no CoTaskMem allocation, no PropVariantClear.
        // The buffer outlives the call because it is a local
        // and SetValue is synchronous.
        let value = PropVariant {
            vt: VT_LPWSTR,
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
            pwsz_val: title.as_ptr(),
            _pad: 0,
        };
        check("IPropertyStore::SetValue(PKEY_Title)", unsafe {
            ps_set_value(store.0, &PKEY_TITLE, &value)
        })?;
        check("IPropertyStore::Commit", unsafe { ps_commit(store.0) })?;
        Ok(link)
    }

    /// Replace `app_id`'s custom jump list with `tasks`:
    /// SetAppID, BeginList, one shell link per task in an object
    /// collection, AddUserTasks, CommitList. A successful commit
    /// replaces the previous custom list wholesale.
    pub fn apply_jump_list(app_id: &str, tasks: &[JumpTask]) -> ShResult<()> {
        let session = ComSession::new()?;
        let list = session.create(
            &CLSID_DESTINATION_LIST,
            &IID_CUSTOM_DESTINATION_LIST,
            "ICustomDestinationList",
        )?;
        let app_id_w = wide(app_id);
        check("ICustomDestinationList::SetAppID", unsafe {
            cdl_set_app_id(list.0, app_id_w.as_ptr())
        })?;
        // BeginList's ppv is a plain [out] parameter in the
        // documentation — it is NOT documented as nullable — so
        // it gets a real pointer (asking for the removed
        // destinations as IObjectArray) and whatever comes back
        // is released immediately; respecting removed items is
        // the caller's data problem, not this apply's.
        let mut min_slots: u32 = 0;
        let mut removed_raw: *mut c_void = std::ptr::null_mut();
        let hr = unsafe { cdl_begin_list(list.0, &mut min_slots, &mut removed_raw) };
        let _removed = ComPtr(removed_raw);
        check("ICustomDestinationList::BeginList", hr)?;
        let result = apply_begun(&session, list.0, tasks);
        if result.is_err() {
            // End the building session cleanly; the error that
            // caused the abort is the one that matters.
            let _ = unsafe { cdl_abort_list(list.0) };
        }
        result
    }

    fn apply_begun(session: &ComSession, list: *mut c_void, tasks: &[JumpTask]) -> ShResult<()> {
        let collection = session.create(
            &CLSID_ENUMERABLE_OBJECT_COLLECTION,
            &IID_OBJECT_COLLECTION,
            "IObjectCollection",
        )?;
        for task in tasks {
            let link = make_task_link(session, task)?;
            check("IObjectCollection::AddObject", unsafe {
                oc_add_object(collection.0, link.0)
            })?;
        }
        // The collection IS an IObjectArray (it extends it), so
        // its pointer is what AddUserTasks takes.
        check("ICustomDestinationList::AddUserTasks", unsafe {
            cdl_add_user_tasks(list, collection.0)
        })?;
        check("ICustomDestinationList::CommitList", unsafe {
            cdl_commit_list(list)
        })?;
        Ok(())
    }

    /// Clear `app_id`'s custom jump list: DeleteList removes
    /// the whole custom list (the shell falls back to its
    /// standard generated list). DeleteList takes the app id as
    /// its own parameter — the form an uninstaller in another
    /// process uses; SetAppID is called first as well, matching
    /// the sequence the interface documents for its other calls.
    pub fn delete_jump_list(app_id: &str) -> ShResult<()> {
        let session = ComSession::new()?;
        let list = session.create(
            &CLSID_DESTINATION_LIST,
            &IID_CUSTOM_DESTINATION_LIST,
            "ICustomDestinationList",
        )?;
        let app_id_w = wide(app_id);
        check("ICustomDestinationList::SetAppID", unsafe {
            cdl_set_app_id(list.0, app_id_w.as_ptr())
        })?;
        check("ICustomDestinationList::DeleteList", unsafe {
            cdl_delete_list(list.0, app_id_w.as_ptr())
        })?;
        Ok(())
    }
}
