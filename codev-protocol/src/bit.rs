use crate::DecodeError;
use std::error::Error;
use std::fmt;

/// A borrowing reader for Unreal's least-significant-bit-first bit archives.
///
/// Ranges point directly into the caller's byte slice; creating a sub-reader
/// never copies or repacks payload bits.
#[derive(Clone, Copy, Debug)]
pub struct Lsb0Reader<'a> {
    data: &'a [u8],
    start_bit: usize,
    bit_length: usize,
    bit_position: usize,
}

impl<'a> Lsb0Reader<'a> {
    pub fn new(data: &'a [u8], bit_length: usize) -> Result<Self, DecodeError> {
        Self::range(data, 0, bit_length)
    }

    pub fn range(data: &'a [u8], start_bit: usize, bit_length: usize) -> Result<Self, DecodeError> {
        let buffer_bits = data.len().saturating_mul(8);
        let end = start_bit
            .checked_add(bit_length)
            .ok_or(DecodeError::ArchiveOutOfRange {
                start_bit,
                bit_length,
                buffer_bits,
            })?;
        if end > buffer_bits {
            return Err(DecodeError::ArchiveOutOfRange {
                start_bit,
                bit_length,
                buffer_bits,
            });
        }
        Ok(Self {
            data,
            start_bit,
            bit_length,
            bit_position: 0,
        })
    }

    #[inline]
    pub const fn position(&self) -> usize {
        self.bit_position
    }

    #[inline]
    pub const fn absolute_position(&self) -> usize {
        self.start_bit + self.bit_position
    }

    #[inline]
    pub const fn bits_left(&self) -> usize {
        self.bit_length - self.bit_position
    }

    #[inline]
    pub fn read_bit(&mut self) -> Result<bool, DecodeError> {
        if self.bit_position == self.bit_length {
            return Err(DecodeError::UnexpectedEof {
                bit_position: self.absolute_position(),
                needed_bits: 1,
                remaining_bits: 0,
            });
        }
        let absolute = self.start_bit + self.bit_position;
        self.bit_position += 1;
        Ok((self.data[absolute >> 3] >> (absolute & 7)) & 1 != 0)
    }

    /// Read at most 32 LSB0 bits into the low bits of a `u32`.
    #[inline]
    pub fn read_bits(&mut self, width: u8) -> Result<u32, DecodeError> {
        if width > 32 {
            return Err(DecodeError::InvalidBitWidth(width));
        }
        let width = usize::from(width);
        if width > self.bits_left() {
            return Err(DecodeError::UnexpectedEof {
                bit_position: self.absolute_position(),
                needed_bits: width,
                remaining_bits: self.bits_left(),
            });
        }

        let mut value = 0_u32;
        let mut remaining = width;
        let mut output_shift = 0_u32;
        while remaining != 0 {
            let absolute = self.start_bit + self.bit_position;
            let byte_shift = absolute & 7;
            let available = 8 - byte_shift;
            let take = remaining.min(available);
            let mask = (1_u16 << take) - 1;
            let chunk = (u16::from(self.data[absolute >> 3]) >> byte_shift) & mask;
            value |= u32::from(chunk) << output_shift;
            self.bit_position += take;
            remaining -= take;
            output_shift += take as u32;
        }
        Ok(value)
    }

    /// Mirror `FBitReader::SerializeInt`.
    pub fn serialize_int(&mut self, maximum: u32) -> Result<u32, DecodeError> {
        if maximum == 0 {
            return Err(DecodeError::InvalidSerializeIntMaximum(maximum));
        }
        let mut value = 0_u32;
        let mut mask = 1_u32;
        loop {
            if self.read_bit()? {
                value |= mask;
            }
            if mask > u32::MAX / 2 || mask.saturating_mul(2).saturating_add(value) >= maximum {
                return Ok(value);
            }
            mask <<= 1;
        }
    }

    /// Read UE's 7-data-bit/low-continuation-bit packed `u32`.
    pub fn serialize_int_packed(&mut self) -> Result<u32, DecodeError> {
        let mut value = 0_u32;
        for group in 0..5_u32 {
            let encoded = self.read_bits(8)?;
            let data = encoded >> 1;
            if group == 4 && data > 0x0f {
                return Err(DecodeError::PackedIntOverflow {
                    bit_position: self.absolute_position() - 8,
                });
            }
            value |= data << (group * 7);
            if encoded & 1 == 0 {
                return Ok(value);
            }
        }
        Err(DecodeError::PackedIntUnterminated {
            bit_position: self.absolute_position(),
        })
    }
}

/// Growable writer for Unreal's least-significant-bit-first bit archives.
///
/// The writer exists primarily for independent wire round-trip proofs.  It
/// writes semantic values into a fresh zeroed buffer; callers cannot satisfy a
/// re-encode check by handing the original byte slice back unchanged.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Lsb0Writer {
    data: Vec<u8>,
    bit_position: usize,
}

impl Lsb0Writer {
    pub fn with_capacity(bit_capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(bit_capacity.div_ceil(8)),
            bit_position: 0,
        }
    }

    pub const fn position(&self) -> usize {
        self.bit_position
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }

    pub fn write_bit(&mut self, value: bool) {
        self.ensure_bits(1);
        if value {
            self.data[self.bit_position >> 3] |= 1 << (self.bit_position & 7);
        }
        self.bit_position += 1;
    }

    /// Write at most 32 low bits in LSB0 order.
    pub fn write_bits(&mut self, value: u32, width: u8) -> Result<(), BitWriteError> {
        if width > 32 {
            return Err(BitWriteError::InvalidBitWidth(width));
        }
        if width < 32 && value >= (1_u32 << width) {
            return Err(BitWriteError::ValueOutOfRange {
                value,
                maximum_exclusive: 1_u32 << width,
            });
        }
        for bit in 0..width {
            self.write_bit(value & (1_u32 << bit) != 0);
        }
        Ok(())
    }

    /// Mirror `FBitWriter::SerializeInt` for a value in `[0, maximum)`.
    pub fn serialize_int(&mut self, value: u32, maximum: u32) -> Result<(), BitWriteError> {
        if maximum == 0 {
            return Err(BitWriteError::InvalidSerializeIntMaximum(maximum));
        }
        if value >= maximum {
            return Err(BitWriteError::ValueOutOfRange {
                value,
                maximum_exclusive: maximum,
            });
        }
        let mut mask = 1_u32;
        loop {
            self.write_bit(value & mask != 0);
            let inclusive_low_mask = mask.saturating_mul(2).saturating_sub(1);
            let partial_value = value & inclusive_low_mask;
            if mask > u32::MAX / 2
                || mask.saturating_mul(2).saturating_add(partial_value) >= maximum
            {
                return Ok(());
            }
            mask <<= 1;
        }
    }

    /// Write UE's 7-data-bit/low-continuation-bit packed `u32`.
    pub fn serialize_int_packed(&mut self, mut value: u32) -> Result<(), BitWriteError> {
        loop {
            let data = value & 0x7f;
            value >>= 7;
            self.write_bits((data << 1) | u32::from(value != 0), 8)?;
            if value == 0 {
                return Ok(());
            }
        }
    }

    /// Copy an arbitrary LSB0 range into this fresh archive.
    pub fn write_bit_slice(
        &mut self,
        data: &[u8],
        start_bit: usize,
        bit_length: usize,
    ) -> Result<(), BitWriteError> {
        let end = start_bit
            .checked_add(bit_length)
            .ok_or(BitWriteError::SourceOutOfRange {
                start_bit,
                bit_length,
                buffer_bits: data.len().saturating_mul(8),
            })?;
        if end > data.len().saturating_mul(8) {
            return Err(BitWriteError::SourceOutOfRange {
                start_bit,
                bit_length,
                buffer_bits: data.len().saturating_mul(8),
            });
        }
        for bit in start_bit..end {
            self.write_bit((data[bit >> 3] >> (bit & 7)) & 1 != 0);
        }
        Ok(())
    }

    fn ensure_bits(&mut self, count: usize) {
        let bytes = self.bit_position.saturating_add(count).div_ceil(8);
        if self.data.len() < bytes {
            self.data.resize(bytes, 0);
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BitWriteError {
    InvalidBitWidth(u8),
    InvalidSerializeIntMaximum(u32),
    ValueOutOfRange {
        value: u32,
        maximum_exclusive: u32,
    },
    SourceOutOfRange {
        start_bit: usize,
        bit_length: usize,
        buffer_bits: usize,
    },
}

impl fmt::Display for BitWriteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBitWidth(width) => {
                write!(formatter, "cannot write {width} bits from a u32")
            }
            Self::InvalidSerializeIntMaximum(maximum) => write!(
                formatter,
                "SerializeInt maximum must be positive, got {maximum}"
            ),
            Self::ValueOutOfRange {
                value,
                maximum_exclusive,
            } => write!(
                formatter,
                "value {value} is outside [0, {maximum_exclusive})"
            ),
            Self::SourceOutOfRange {
                start_bit,
                bit_length,
                buffer_bits,
            } => write!(
                formatter,
                "source range {start_bit}+{bit_length} exceeds {buffer_bits} buffer bits"
            ),
        }
    }
}

impl Error for BitWriteError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_unaligned_lsb0_without_copying() {
        let data = [0b1101_0110, 0b0011_0101];
        let mut reader = Lsb0Reader::range(&data, 3, 9).unwrap();
        assert_eq!(reader.read_bits(4).unwrap(), 0b1010);
        assert_eq!(reader.read_bits(5).unwrap(), 0b01011);
        assert_eq!(reader.bits_left(), 0);
    }

    #[test]
    fn packed_integer_is_bounded_to_u32() {
        let mut valid = Lsb0Reader::new(&[0x91, 0x08], 16).unwrap();
        assert_eq!(valid.serialize_int_packed().unwrap(), 584);

        let mut overflow = Lsb0Reader::new(&[1, 1, 1, 1, 0x20], 40).unwrap();
        assert!(matches!(
            overflow.serialize_int_packed(),
            Err(DecodeError::PackedIntOverflow { .. })
        ));
    }

    #[test]
    fn writer_round_trips_unaligned_bits_and_integer_codecs() {
        let mut writer = Lsb0Writer::with_capacity(64);
        writer.write_bits(0b10101, 5).unwrap();
        writer.serialize_int(11, 15).unwrap();
        writer.serialize_int_packed(16_777).unwrap();

        let mut reader = Lsb0Reader::new(writer.as_bytes(), writer.position()).unwrap();
        assert_eq!(reader.read_bits(5).unwrap(), 0b10101);
        assert_eq!(reader.serialize_int(15).unwrap(), 11);
        assert_eq!(reader.serialize_int_packed().unwrap(), 16_777);
        assert_eq!(reader.bits_left(), 0);
    }

    #[test]
    fn writer_rejects_values_that_do_not_fit_the_wire_contract() {
        let mut writer = Lsb0Writer::default();
        assert!(matches!(
            writer.write_bits(8, 3),
            Err(BitWriteError::ValueOutOfRange { .. })
        ));
        assert!(matches!(
            writer.serialize_int(4, 4),
            Err(BitWriteError::ValueOutOfRange { .. })
        ));
        assert!(matches!(
            writer.write_bit_slice(&[0], 7, 2),
            Err(BitWriteError::SourceOutOfRange { .. })
        ));
    }
}
