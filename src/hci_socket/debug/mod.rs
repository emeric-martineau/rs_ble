use std::fmt;

pub struct HciSocketDebug<'a>(pub &'a [u8]);

impl<'a> fmt::Debug for HciSocketDebug<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        if self.0.len() > 0 {
            write!(fmt, "0x")?;

            for &c in self.0 {
                write!(fmt, "{:02x}", c)?;
            }
        }

        Ok(())
    }
}