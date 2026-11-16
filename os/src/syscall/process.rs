//! Process management syscalls
use crate::mm::{translated_ref, translated_refmut, MapPermission};
use crate::task::{
    change_program_brk, current_user_token, exit_current_and_run_next,
    get_current_syscall_count, map_current_user_area, suspend_current_and_run_next,
    unmap_current_user_area,
};
use crate::timer::get_time_us;

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

/// task exits and submit an exit code
pub fn sys_exit(_exit_code: i32) -> ! {
    trace!("kernel: sys_exit");
    exit_current_and_run_next();
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel: sys_yield");
    suspend_current_and_run_next();
    0
}

/// Get time with second and microsecond.
pub fn sys_get_time(ts: *mut TimeVal, _tz: usize) -> isize {
    trace!("kernel: sys_get_time");
    let token = current_user_token();
    let us = get_time_us();
    for (index, value) in [us / 1_000_000, us % 1_000_000].iter().enumerate() {
        let ptr = (ts as usize + index * core::mem::size_of::<usize>()) as *mut usize;
        let Some(slot) = translated_refmut(token, ptr) else {
            return -1;
        };
        *slot = *value;
    }
    0
}

/// Read/write a user byte, or query the number of syscalls by ID.
pub fn sys_trace(trace_request: usize, id: usize, data: usize) -> isize {
    trace!("kernel: sys_trace");
    let token = current_user_token();
    match trace_request {
        0 => translated_ref(token, id as *const u8)
            .map(|value| *value as isize)
            .unwrap_or(-1),
        1 => match translated_refmut(token, id as *mut u8) {
            Some(value) => {
                *value = data as u8;
                0
            }
            None => -1,
        },
        2 => get_current_syscall_count(id) as isize,
        _ => -1,
    }
}

/// Map page-aligned user memory with R/W/X permissions.
pub fn sys_mmap(start: usize, len: usize, prot: usize) -> isize {
    trace!("kernel: sys_mmap");
    if len == 0
        || start % 4096 != 0
        || prot == 0
        || prot & !7 != 0
        || len.checked_add(4095).is_none()
    {
        return -1;
    }
    let aligned_len = (len + 4095) / 4096 * 4096;
    let Some(end) = start.checked_add(aligned_len) else {
        return -1;
    };
    let mut permission = MapPermission::U;
    if prot & 1 != 0 {
        permission |= MapPermission::R;
    }
    if prot & 2 != 0 {
        permission |= MapPermission::W;
    }
    if prot & 4 != 0 {
        permission |= MapPermission::X;
    }
    if map_current_user_area(start, end, permission) {
        0
    } else {
        -1
    }
}

/// Unmap an exact page-aligned user area.
pub fn sys_munmap(start: usize, len: usize) -> isize {
    trace!("kernel: sys_munmap");
    if len == 0
        || start % 4096 != 0
        || len % 4096 != 0
        || start.checked_add(len).is_none()
        || !unmap_current_user_area(start, start + len)
    {
        -1
    } else {
        0
    }
}
/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel: sys_sbrk");
    if let Some(old_brk) = change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}
