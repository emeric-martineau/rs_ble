//! Logger for Hci Bluetooth.
//!

/// Trait of logger.
pub trait HciLogger {
    /// Is debug level is enable.
    fn is_debug_enable(&self) -> bool;

    /// Print debug message.
    fn debug(&self, expr: &str);
}

/// This log display nothing.
pub struct NullLogger;


impl HciLogger for NullLogger {
    fn is_debug_enable(&self) -> bool {
        false
    }

    fn debug(&self, _expr: &str) {}
}

/// This log display on stdout.
pub struct ConsoleLogger {
    pub debug_level: bool
}

impl HciLogger for ConsoleLogger {
    fn is_debug_enable(&self) -> bool {
        self.debug_level
    }

    fn debug(&self, expr: &str) {
        if self.debug_level {
            println!("{}", expr);
        }
    }
}