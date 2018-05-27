macro_rules! cprintln {
    ($suppress:expr, $stdout:expr, $fg:expr, $($rest:tt)+) => {
        if !$suppress {
            use std::io::Write;
            use termcolor::{ColorSpec, WriteColor};

            $stdout.set_color(ColorSpec::new().set_fg(Some($fg)))
                .expect("Could not set the text formatting.");
            writeln!($stdout, $($rest)+).expect("Could not output text.");
        }
    }
}

macro_rules! cprint {
    ($suppress:expr, $stdout:expr, $fg:expr, $($rest:tt)+) => {
        if !$suppress {
            use std::io::Write;
            use termcolor::{ColorSpec, WriteColor};

            $stdout.set_color(ColorSpec::new().set_fg(Some($fg)))
                .expect("Could not set the text formatting.");
            write!($stdout, $($rest)+).expect("Could not output text.");
        }
    }
}
