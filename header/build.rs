extern crate bindgen;
extern crate glob;

use std::path::{Path, PathBuf};
use glob::{glob, PatternError};

fn dir_list_file(dir: &str, pattern: &str) -> Result<Vec<String>, PatternError> {
    let mut new_dir = String::from(dir);

    if !dir.ends_with("/") {
        new_dir.push_str("/");
    }

    new_dir.push_str(pattern);

    match glob(&new_dir) {
        Ok(all_files) => {
            let mut result: Vec<String> = Vec::new();

            for entry in all_files {
                if let Ok(path) = entry {
                    let f = path.display().to_string();

                    result.push(f);
                }
            }

            Ok(result)
        }
        Err(e) => Err(e),
    }
}

fn main() {
    match dir_list_file("./include", "*.h") {
        Ok(files_list) => {
            for file in files_list {
                // The bindgen::Builder is the main entry point
                // to bindgen, and lets you build up options for
                // the resulting bindings.
                let bindings = bindgen::Builder::default()
                    // The input header we would like to generate
                    // bindings for.
                    .header(file.clone())
                    // Finish the builder and generate the bindings.
                    .generate()
                    // Unwrap the Result and panic on failure.
                    .expect("Unable to generate bindings");

                let path = Path::new(&file);
                let filename = path.file_stem().unwrap().to_str().unwrap();

                let out_path = PathBuf::from(format!("./src/{}.rs", filename));

                bindings
                    .write_to_file(out_path)
                    .expect("Couldn't write bindings!");
            }
        },
        Err(e) => panic!(e)
    }
}
