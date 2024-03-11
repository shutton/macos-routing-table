fn main() -> Result<(), std::io::Error> {
    let sample_table = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/sample-tables/sample-table.txt"
    ))?;

    let sample_table = format!("const SAMPLE_TABLE: &str = {sample_table:?};\n");

    let out_dir = std::env::var("OUT_DIR").expect("env OUT_DIR");
    std::fs::write(
        format!("{out_dir}/sample_table.rs"),
        sample_table.as_bytes(),
    )?;

    Ok(())
}
