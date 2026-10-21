//! Deterministic build-time assets. Original IEEE CSVs and the master logo stay in the tree.
use flate2::{Compression, write::ZlibEncoder};
use std::{collections::BTreeMap, fs, io::Write, path::Path};

pub fn generate(out: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let mut vendors = BTreeMap::new();
    let mut source_bytes = 0;
    for (bits, path) in [
        (24u8, "assets/oui.csv"),
        (28, "assets/mam.csv"),
        (36, "assets/oui36.csv"),
    ] {
        println!("cargo:rerun-if-changed={path}");
        source_bytes += fs::metadata(path)?.len();
        let mut csv = csv::Reader::from_path(path)?;
        for record in csv.records() {
            let record = record?;
            let prefix = u64::from_str_radix(record.get(1).ok_or("missing IEEE assignment")?, 16)?;
            if prefix >= (1u64 << bits) {
                return Err(format!("invalid {bits}-bit prefix in {path}").into());
            }
            let name = record.get(2).ok_or("missing IEEE organization name")?;
            if name.len() > 16_384 {
                return Err(format!("IEEE organization name too long in {path}").into());
            }
            // Keep the old parser's last-entry-wins behavior, names and all three prefix lengths.
            vendors.insert((bits, prefix), name.to_owned());
        }
    }
    let mut packed = ZlibEncoder::new(Vec::new(), Compression::best());
    packed.write_all(b"IPSCIE01")?;
    packed.write_all(&u32::try_from(vendors.len())?.to_be_bytes())?;
    let mut raw_bytes = 12;
    for ((bits, prefix), name) in &vendors {
        packed.write_all(&[*bits])?;
        packed.write_all(&prefix.to_be_bytes())?;
        packed.write_all(&u32::try_from(name.len())?.to_be_bytes())?;
        packed.write_all(name.as_bytes())?;
        raw_bytes += 13 + name.len();
    }
    let packed = packed.finish()?;
    fs::write(out.join("ieee-vendors.zlib"), &packed)?;

    // Reuse the exact PNG already used by Explorer at 256px. No resampling, palette
    // reduction or alpha changes here, and no image converter is required for a build.
    let icon = fs::read("assets/ip-scout.ico")?;
    if icon.get(..4) != Some(&[0, 0, 1, 0]) {
        return Err("invalid ICO header".into());
    }
    let count =
        u16::from_le_bytes(icon.get(4..6).ok_or("truncated ICO header")?.try_into()?) as usize;
    let mut logo = None;
    for index in 0..count {
        let start = 6 + index * 16;
        let entry = icon
            .get(start..start + 16)
            .ok_or("truncated ICO directory")?;
        if entry[0] != 0 || entry[1] != 0 {
            continue;
        }
        let size = u32::from_le_bytes(entry[8..12].try_into()?) as usize;
        let offset = u32::from_le_bytes(entry[12..16].try_into()?) as usize;
        let end = offset.checked_add(size).ok_or("invalid ICO image size")?;
        let png = icon.get(offset..end).ok_or("truncated ICO image")?;
        if !png.starts_with(b"\x89PNG\r\n\x1a\n")
            || png.get(16..24) != Some(&[0, 0, 1, 0, 0, 0, 1, 0])
        {
            return Err("ICO must contain a 256x256 PNG".into());
        }
        logo = Some(png);
        break;
    }
    let logo = logo.ok_or("ICO is missing its 256px PNG frame; run scripts/create-icon.ps1")?;
    fs::write(out.join("runtime-logo.png"), logo)?;
    fs::write(
        out.join("asset-sizes.json"),
        format!(
            "{{\n  \"ieee_source_bytes\": {source_bytes},\n  \"ieee_entries\": {},\n  \"ieee_binary_bytes\": {raw_bytes},\n  \"ieee_embedded_bytes\": {},\n  \"logo_source_bytes\": {},\n  \"logo_embedded_bytes\": {},\n  \"logo_width\": 256,\n  \"logo_height\": 256\n}}\n",
            vendors.len(),
            packed.len(),
            fs::metadata("assets/ip-scout-logo.png")?.len(),
            logo.len()
        ),
    )?;
    Ok(())
}
