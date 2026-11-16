//!Implementation of [`TaskManager`]
use super::TaskControlBlock;
use crate::sync::UPSafeCell;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use lazy_static::*;
///A array of `TaskControlBlock` that is thread-safe
pub struct TaskManager {
    ready_queue: VecDeque<Arc<TaskControlBlock>>,
    stop_task: Option<Arc<TaskControlBlock>>,
}

/// A simple FIFO scheduler.
impl TaskManager {
    ///Creat an empty TaskManager
    pub fn new() -> Self {
        Self {
            ready_queue: VecDeque::new(),
            stop_task: None,
        }
    }
    /// Add process back to ready queue
    pub fn add(&mut self, task: Arc<TaskControlBlock>) {
        self.ready_queue.push_back(task);
    }
    /// Take a process out of the ready queue
    pub fn fetch(&mut self) -> Option<Arc<TaskControlBlock>> {
        let index = self
            .ready_queue
            .iter()
            .enumerate()
            .min_by_key(|(_, task)| task.inner_exclusive_access().stride)
            .map(|(index, _)| index)?;
        self.ready_queue.remove(index)
    }
    /// Keep the exiting task alive until another task starts using a different stack.
    pub fn add_stop(&mut self, task: Arc<TaskControlBlock>) {
        self.stop_task = Some(task);
    }
    fn clear_stop(&mut self, task: &Arc<TaskControlBlock>) {
        if self
            .stop_task
            .as_ref()
            .is_some_and(|stopped| Arc::as_ptr(stopped) == Arc::as_ptr(task))
        {
            self.stop_task = None;
        }
    }
}

lazy_static! {
    /// TASK_MANAGER instance through lazy_static!
    pub static ref TASK_MANAGER: UPSafeCell<TaskManager> =
        unsafe { UPSafeCell::new(TaskManager::new()) };
}

/// Add process to ready queue
pub fn add_task(task: Arc<TaskControlBlock>) {
    //trace!("kernel: TaskManager::add_task");
    TASK_MANAGER.exclusive_access().add(task);
}

/// Take a process out of the ready queue
pub fn fetch_task() -> Option<Arc<TaskControlBlock>> {
    //trace!("kernel: TaskManager::fetch_task");
    TASK_MANAGER.exclusive_access().fetch()
}

/// Retain the task whose kernel stack is currently in use.
pub fn add_stopping_task(task: Arc<TaskControlBlock>) {
    TASK_MANAGER.exclusive_access().add_stop(task);
}

/// Drop a retained stopped task once its zombie record is being collected.
pub fn clear_stopping_task(task: &Arc<TaskControlBlock>) {
    TASK_MANAGER.exclusive_access().clear_stop(task);
}
