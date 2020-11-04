const HEX_LENGTH: usize = 80 - 6 /* indentation */ - 3 /* quotes, comma */ - 1 /* Make it even */;
const BYTES_PER_ROW: usize = HEX_LENGTH / 2;

pub(crate) fn write_hex(mut target: impl std::fmt::Write, byte: u8) {
    let high = (byte & 0xf0) >> 4;
    let low = byte & 0x0f;

    for part in &[high, low] {
        write!(target, "{:x}", part).unwrap();
    }
}

pub(crate) fn to_hex_vec(bytes: &[u8]) -> Vec<String> {
    let row_count = (bytes.len() + BYTES_PER_ROW - 1) / BYTES_PER_ROW;

    let mut rows = Vec::with_capacity(row_count);

    let mut iter = bytes.iter();
    for row in 0..row_count {
        let mut s = String::with_capacity(HEX_LENGTH);

        let previous = row * BYTES_PER_ROW;
        let remain = bytes.len().saturating_sub(previous);
        let col_count = std::cmp::min(BYTES_PER_ROW, remain);
        for _ in 0..col_count {
            if let Some(&byte) = iter.next() {
                write_hex(&mut s, byte);
            }
        }

        rows.push(s);
    }

    rows
}
