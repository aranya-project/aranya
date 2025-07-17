use std::{
    error::Error,
    fmt::{self, Display, Write},
};

/// Extension trait for formatting an error with source chain.
pub trait ReportExt {
    /// Display this error with source chain.
    fn report(&self) -> impl Display;
}

impl<E> ReportExt for E
where
    E: Error,
{
    fn report(&self) -> impl Display {
        ReportImpl(self)
    }
}

// Implementation taken from `anyhow`.

struct ReportImpl<E>(E);

impl<E: Error> Display for ReportImpl<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let error = &self.0;

        write!(f, "{error}")?;

        if let Some(cause) = error.source() {
            write!(f, "\n\nCaused by:")?;
            let multiple = cause.source().is_some();
            for (n, error) in anyhow::Chain::new(cause).enumerate() {
                writeln!(f)?;
                let mut indented = Indented {
                    inner: f,
                    number: multiple.then_some(n),
                    started: false,
                };
                write!(indented, "{error}")?;
            }
        }

        Ok(())
    }
}

struct Indented<'a, D> {
    inner: &'a mut D,
    number: Option<usize>,
    started: bool,
}

impl<T> Write for Indented<'_, T>
where
    T: Write,
{
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for (i, line) in s.split('\n').enumerate() {
            if !self.started {
                self.started = true;
                match self.number {
                    Some(number) => write!(self.inner, "{number: >5}: ")?,
                    None => self.inner.write_str("    ")?,
                }
            } else if i > 0 {
                self.inner.write_char('\n')?;
                if self.number.is_some() {
                    self.inner.write_str("       ")?;
                } else {
                    self.inner.write_str("    ")?;
                }
            }

            self.inner.write_str(line)?;
        }

        Ok(())
    }
}
