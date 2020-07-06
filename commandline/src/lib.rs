// prints status
macro_rules! print_status {
    ($data:expr) => {{
        use std::io::{self, Write};
        let mut stdout = io::stdout();
        let _ = stdout.write($data);
        let _ = stdout.flush();
    }};
}

// creates error description with file and line.
macro_rules! line_error {
    () => {
        concat!("Error at ", file!(), ":", line!())
    };
}

mod shared;
