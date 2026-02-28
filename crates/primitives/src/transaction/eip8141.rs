//! EIP-8141: Frame Transaction types.
//!
//! Frame transactions (type 0x06) enable composable execution with
//! multiple frames. Each frame targets a contract with a specific mode:
//! - **VERIFY** (1): Must call the APPROVE opcode to authorize the sender.
//! - **DEFAULT** (0): Executes from ENTRY_POINT.
//! - **SENDER** (2): Executes from tx.sender (requires prior sender approval).
//!
//! No ECDSA signature — the sender is explicit in the transaction.
//!
//! ## RLP Encoding
//! ```text
//! 0x06 || rlp([chain_id, nonce, sender, frames, max_priority_fee_per_gas,
//!              max_fee_per_gas, max_fee_per_blob_gas, blob_versioned_hashes])
//! ```

use alloy_consensus::Transaction;
use alloy_eips::eip2718::Typed2718;
use alloy_primitives::{Address, B256, Bytes, Keccak256, TxKind, U256};
use alloy_rlp::{BufMut, Decodable, Encodable, Header};
use core::mem;

// ─── Constants ──────────────────────────────────────────────────────────────

/// The EIP-8141 transaction type byte.
pub const EIP8141_TX_TYPE_ID: u8 = 0x06;

/// Intrinsic gas cost for frame transactions.
pub const FRAME_TX_INTRINSIC_COST: u64 = 15_000;

/// Maximum number of frames per transaction.
pub const MAX_FRAMES: usize = 1_000;

/// Entry point address for DEFAULT and VERIFY frames.
pub const ENTRY_POINT: Address = {
    let mut addr = [0u8; 20];
    addr[19] = 0xaa;
    Address::new(addr)
};

// ─── Frame Mode ─────────────────────────────────────────────────────────────

/// Execution mode for a frame within a frame transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum FrameMode {
    /// Standard call with ENTRY_POINT as caller.
    Default = 0,
    /// Validation frame (runs as STATICCALL, must call APPROVE).
    Verify = 1,
    /// Executes with tx.sender as caller (requires prior sender approval).
    Sender = 2,
}

impl FrameMode {
    /// Try to convert from a u8 value.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Default),
            1 => Some(Self::Verify),
            2 => Some(Self::Sender),
            _ => None,
        }
    }
}

// ─── Frame ──────────────────────────────────────────────────────────────────

/// A single frame within an EIP-8141 frame transaction.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Frame {
    /// Execution mode (0=DEFAULT, 1=VERIFY, 2=SENDER).
    pub mode: u8,
    /// Optional target contract address. `None` means sender address.
    pub target: Option<Address>,
    /// Gas limit for this frame.
    pub gas_limit: u64,
    /// Calldata for this frame.
    pub data: Bytes,
}

impl Encodable for Frame {
    fn encode(&self, out: &mut dyn BufMut) {
        let target_len = self.target.map_or_else(|| Bytes::new().length(), |t| t.length());
        alloy_rlp::Header {
            list: true,
            payload_length: self.mode.length()
                + target_len
                + self.gas_limit.length()
                + self.data.length(),
        }
        .encode(out);
        self.mode.encode(out);
        if let Some(target) = self.target {
            target.encode(out);
        } else {
            // Null target is encoded as empty bytes.
            Bytes::new().encode(out);
        }
        self.gas_limit.encode(out);
        self.data.encode(out);
    }

    fn length(&self) -> usize {
        let target_len = self.target.map_or_else(|| Bytes::new().length(), |t| t.length());
        let payload_length =
            self.mode.length() + target_len + self.gas_limit.length() + self.data.length();
        payload_length + alloy_rlp::length_of_length(payload_length)
    }
}

impl Decodable for Frame {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let header = alloy_rlp::Header::decode(buf)?;
        if !header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        let remaining_before = buf.len();
        let mode = u8::decode(buf)?;
        let target_bytes = Bytes::decode(buf)?;
        let target = if target_bytes.is_empty() {
            None
        } else if target_bytes.len() == 20 {
            Some(Address::from_slice(target_bytes.as_ref()))
        } else {
            return Err(alloy_rlp::Error::Custom(
                "EIP-8141: frame target must be null or 20-byte address",
            ));
        };
        let gas_limit = u64::decode(buf)?;
        let data = Bytes::decode(buf)?;
        let consumed = remaining_before - buf.len();
        if consumed != header.payload_length {
            return Err(alloy_rlp::Error::ListLengthMismatch {
                expected: header.payload_length,
                got: consumed,
            });
        }
        Ok(Self { mode, target, gas_limit, data })
    }
}

// ─── TxEip8141 ─────────────────────────────────────────────────────────────

/// EIP-8141 Frame Transaction.
///
/// A new transaction type (0x06) that enables flexible validation and payment
/// mechanisms through composable execution frames.
///
/// ## RLP Encoding
/// ```text
/// 0x06 || rlp([chain_id, nonce, sender, frames, max_priority_fee_per_gas,
///              max_fee_per_gas, max_fee_per_blob_gas, blob_versioned_hashes])
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct TxEip8141 {
    /// Chain ID.
    pub chain_id: u64,
    /// Transaction nonce.
    pub nonce: u64,
    /// Explicit sender address (no signature recovery needed).
    pub sender: Address,
    /// Ordered list of execution frames.
    pub frames: Vec<Frame>,
    /// EIP-1559 max priority fee per gas.
    pub max_priority_fee_per_gas: u128,
    /// EIP-1559 max fee per gas.
    pub max_fee_per_gas: u128,
    /// EIP-4844 max fee per blob gas (0 if no blobs).
    pub max_fee_per_blob_gas: u128,
    /// EIP-4844 blob versioned hashes (empty if no blobs).
    pub blob_versioned_hashes: Vec<B256>,
}

impl TxEip8141 {
    /// Returns calldata gas cost for `rlp(frames)`.
    pub fn frames_calldata_cost(&self) -> u64 {
        const ZERO_BYTE_GAS: u64 = 4;
        const NON_ZERO_BYTE_GAS: u64 = 16;

        let mut encoded = Vec::new();
        let frames_payload: usize = self.frames.iter().map(|f| f.length()).sum();
        Header { list: true, payload_length: frames_payload }.encode(&mut encoded);
        for frame in &self.frames {
            frame.encode(&mut encoded);
        }

        encoded.into_iter().fold(0u64, |acc, b| {
            acc.saturating_add(if b == 0 { ZERO_BYTE_GAS } else { NON_ZERO_BYTE_GAS })
        })
    }

    /// Returns the total gas limit (intrinsic + sum of all frame gas limits).
    pub fn total_gas_limit(&self) -> u64 {
        FRAME_TX_INTRINSIC_COST
            .saturating_add(self.frames.iter().map(|f| f.gas_limit).sum::<u64>())
            .saturating_add(self.frames_calldata_cost())
    }

    /// Computes the signature hash.
    ///
    /// VERIFY frame data is zeroed out before hashing so that the hash
    /// commits to frame targets but not the verification data itself.
    pub fn signature_hash(&self) -> B256 {
        let mut hasher = Keccak256::new();
        hasher.update([EIP8141_TX_TYPE_ID]);

        let mut modified = self.clone();
        for frame in &mut modified.frames {
            if frame.mode == FrameMode::Verify as u8 {
                frame.data = Bytes::default();
            }
        }

        let mut rlp_buf = Vec::new();
        modified.encode(&mut rlp_buf);
        hasher.update(&rlp_buf);
        hasher.finalize()
    }

    /// Computes the transaction hash (keccak256 of the full EIP-2718 encoding).
    pub fn tx_hash(&self) -> B256 {
        let mut hasher = Keccak256::new();
        hasher.update([EIP8141_TX_TYPE_ID]);
        let mut rlp_buf = Vec::new();
        self.encode(&mut rlp_buf);
        hasher.update(&rlp_buf);
        hasher.finalize()
    }

    /// Estimate in-memory size of this transaction.
    pub fn size(&self) -> usize {
        mem::size_of::<Self>()
            + self.frames.capacity() * mem::size_of::<Frame>()
            + self.frames.iter().map(|f| f.data.len()).sum::<usize>()
            + self.blob_versioned_hashes.capacity() * mem::size_of::<B256>()
    }

    /// Validates the transaction structure.
    ///
    /// Checks:
    /// - Non-empty frame list
    /// - Frame count <= MAX_FRAMES
    /// - All frame modes are valid (0, 1, or 2)
    /// - Gas limit sum doesn't overflow u64
    /// - `max_fee_per_gas >= max_priority_fee_per_gas`
    pub fn validate(&self) -> Result<(), Eip8141ValidationError> {
        if self.frames.is_empty() {
            return Err(Eip8141ValidationError::NoFrames);
        }

        if self.frames.len() > MAX_FRAMES {
            return Err(Eip8141ValidationError::TooManyFrames {
                count: self.frames.len(),
                max: MAX_FRAMES,
            });
        }

        let mut gas_total: u64 = FRAME_TX_INTRINSIC_COST;

        for (i, frame) in self.frames.iter().enumerate() {
            if FrameMode::from_u8(frame.mode).is_none() {
                return Err(Eip8141ValidationError::InvalidFrameMode {
                    index: i,
                    mode: frame.mode,
                });
            }

            gas_total = gas_total
                .checked_add(frame.gas_limit)
                .ok_or(Eip8141ValidationError::GasLimitOverflow)?;
        }

        let _ = gas_total
            .checked_add(self.frames_calldata_cost())
            .ok_or(Eip8141ValidationError::GasLimitOverflow)?;

        if self.max_fee_per_gas < self.max_priority_fee_per_gas {
            return Err(Eip8141ValidationError::MaxFeeBelowPriority);
        }

        Ok(())
    }

    fn rlp_payload_length(&self) -> usize {
        self.chain_id.length()
            + self.nonce.length()
            + self.sender.length()
            + self.frames_rlp_length()
            + self.max_priority_fee_per_gas.length()
            + self.max_fee_per_gas.length()
            + self.max_fee_per_blob_gas.length()
            + self.blob_hashes_rlp_length()
    }

    fn frames_rlp_length(&self) -> usize {
        let payload: usize = self.frames.iter().map(|f| f.length()).sum();
        payload + alloy_rlp::length_of_length(payload)
    }

    fn blob_hashes_rlp_length(&self) -> usize {
        let payload: usize = self.blob_versioned_hashes.iter().map(|h| h.length()).sum();
        payload + alloy_rlp::length_of_length(payload)
    }
}

// ─── Validation Error ──────────────────────────────────────────────────────

/// Validation errors for EIP-8141 frame transactions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Eip8141ValidationError {
    /// Transaction has no frames.
    NoFrames,
    /// Too many frames in the transaction.
    TooManyFrames { count: usize, max: usize },
    /// Invalid frame mode byte.
    InvalidFrameMode { index: usize, mode: u8 },
    /// Sum of frame gas limits overflows u64.
    GasLimitOverflow,
    /// `max_fee_per_gas` is less than `max_priority_fee_per_gas`.
    MaxFeeBelowPriority,
}

impl core::fmt::Display for Eip8141ValidationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoFrames => write!(f, "EIP-8141: transaction has no frames"),
            Self::TooManyFrames { count, max } => {
                write!(f, "EIP-8141: too many frames ({count} > {max})")
            }
            Self::InvalidFrameMode { index, mode } => {
                write!(f, "EIP-8141: invalid frame mode {mode} at index {index}")
            }
            Self::GasLimitOverflow => write!(f, "EIP-8141: gas limit sum overflows u64"),
            Self::MaxFeeBelowPriority => {
                write!(f, "EIP-8141: max_fee_per_gas < max_priority_fee_per_gas")
            }
        }
    }
}

// ─── RLP Encoding ───────────────────────────────────────────────────────────

impl Encodable for TxEip8141 {
    fn encode(&self, out: &mut dyn BufMut) {
        let payload_length = self.rlp_payload_length();
        alloy_rlp::Header { list: true, payload_length }.encode(out);

        self.chain_id.encode(out);
        self.nonce.encode(out);
        self.sender.encode(out);

        // Encode frames as a list
        let frames_payload: usize = self.frames.iter().map(|f| f.length()).sum();
        alloy_rlp::Header { list: true, payload_length: frames_payload }.encode(out);
        for frame in &self.frames {
            frame.encode(out);
        }

        self.max_priority_fee_per_gas.encode(out);
        self.max_fee_per_gas.encode(out);
        self.max_fee_per_blob_gas.encode(out);

        // Encode blob_versioned_hashes as a list
        let blob_payload: usize = self.blob_versioned_hashes.iter().map(|h| h.length()).sum();
        alloy_rlp::Header { list: true, payload_length: blob_payload }.encode(out);
        for hash in &self.blob_versioned_hashes {
            hash.encode(out);
        }
    }

    fn length(&self) -> usize {
        let payload_length = self.rlp_payload_length();
        payload_length + alloy_rlp::length_of_length(payload_length)
    }
}

impl Decodable for TxEip8141 {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let header = alloy_rlp::Header::decode(buf)?;
        if !header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        let remaining_before = buf.len();

        let chain_id = u64::decode(buf)?;
        let nonce = u64::decode(buf)?;
        let sender = Address::decode(buf)?;

        // Decode frames list
        let frames_header = alloy_rlp::Header::decode(buf)?;
        if !frames_header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        let mut frames = Vec::new();
        let frames_end = buf.len() - frames_header.payload_length;
        while buf.len() > frames_end {
            frames.push(Frame::decode(buf)?);
        }

        let max_priority_fee_per_gas = u128::decode(buf)?;
        let max_fee_per_gas = u128::decode(buf)?;
        let max_fee_per_blob_gas = u128::decode(buf)?;

        // Decode blob_versioned_hashes list
        let blob_header = alloy_rlp::Header::decode(buf)?;
        if !blob_header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        let mut blob_versioned_hashes = Vec::new();
        let blob_end = buf.len() - blob_header.payload_length;
        while buf.len() > blob_end {
            blob_versioned_hashes.push(B256::decode(buf)?);
        }

        let consumed = remaining_before - buf.len();
        if consumed != header.payload_length {
            return Err(alloy_rlp::Error::ListLengthMismatch {
                expected: header.payload_length,
                got: consumed,
            });
        }

        Ok(Self {
            chain_id,
            nonce,
            sender,
            frames,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            max_fee_per_blob_gas,
            blob_versioned_hashes,
        })
    }
}

// ─── alloy_consensus::Transaction impl ─────────────────────────────────────

impl Transaction for TxEip8141 {
    fn chain_id(&self) -> Option<u64> {
        Some(self.chain_id)
    }

    fn nonce(&self) -> u64 {
        self.nonce
    }

    fn gas_limit(&self) -> u64 {
        self.total_gas_limit()
    }

    fn gas_price(&self) -> Option<u128> {
        None
    }

    fn max_fee_per_gas(&self) -> u128 {
        self.max_fee_per_gas
    }

    fn max_priority_fee_per_gas(&self) -> Option<u128> {
        Some(self.max_priority_fee_per_gas)
    }

    fn max_fee_per_blob_gas(&self) -> Option<u128> {
        if self.blob_versioned_hashes.is_empty() { None } else { Some(self.max_fee_per_blob_gas) }
    }

    fn priority_fee_or_price(&self) -> u128 {
        self.max_priority_fee_per_gas
    }

    fn effective_gas_price(&self, base_fee: Option<u64>) -> u128 {
        if let Some(base_fee) = base_fee {
            let tip = self
                .max_fee_per_gas
                .saturating_sub(base_fee as u128)
                .min(self.max_priority_fee_per_gas);
            tip + base_fee as u128
        } else {
            self.max_fee_per_gas
        }
    }

    fn is_dynamic_fee(&self) -> bool {
        true
    }

    fn kind(&self) -> TxKind {
        for frame in &self.frames {
            if frame.mode != FrameMode::Verify as u8 {
                return TxKind::Call(frame.target.unwrap_or(self.sender));
            }
        }
        TxKind::Call(self.sender)
    }

    fn value(&self) -> U256 {
        U256::ZERO
    }

    fn input(&self) -> &Bytes {
        static EMPTY: Bytes = Bytes::new();
        for frame in &self.frames {
            if frame.mode != FrameMode::Verify as u8 {
                return &frame.data;
            }
        }
        self.frames.first().map_or(&EMPTY, |f| &f.data)
    }

    fn is_create(&self) -> bool {
        false
    }

    fn access_list(&self) -> Option<&alloy_eips::eip2930::AccessList> {
        None
    }

    fn blob_versioned_hashes(&self) -> Option<&[B256]> {
        if self.blob_versioned_hashes.is_empty() { None } else { Some(&self.blob_versioned_hashes) }
    }

    fn authorization_list(&self) -> Option<&[alloy_eips::eip7702::SignedAuthorization]> {
        None
    }
}

// ─── Typed2718 impl ─────────────────────────────────────────────────────────

impl Typed2718 for TxEip8141 {
    fn ty(&self) -> u8 {
        EIP8141_TX_TYPE_ID
    }
}

// ─── Sealable impl ─────────────────────────────────────────────────────────

impl alloy_primitives::Sealable for TxEip8141 {
    fn hash_slow(&self) -> B256 {
        self.tx_hash()
    }
}

// ─── Encodable2718 / Decodable2718 ─────────────────────────────────────────

impl alloy_eips::eip2718::Encodable2718 for TxEip8141 {
    fn type_flag(&self) -> Option<u8> {
        Some(EIP8141_TX_TYPE_ID)
    }

    fn encode_2718_len(&self) -> usize {
        1 + self.length()
    }

    fn encode_2718(&self, out: &mut dyn BufMut) {
        out.put_u8(EIP8141_TX_TYPE_ID);
        self.encode(out);
    }
}

impl alloy_eips::eip2718::Decodable2718 for TxEip8141 {
    fn typed_decode(ty: u8, data: &mut &[u8]) -> alloy_eips::eip2718::Eip2718Result<Self> {
        if ty != EIP8141_TX_TYPE_ID {
            return Err(alloy_eips::eip2718::Eip2718Error::UnexpectedType(ty));
        }
        let tx = Self::decode(data).map_err(alloy_eips::eip2718::Eip2718Error::RlpError)?;
        tx.validate().map_err(|_| {
            alloy_eips::eip2718::Eip2718Error::RlpError(alloy_rlp::Error::Custom(
                "EIP-8141 validation failed",
            ))
        })?;
        Ok(tx)
    }

    fn fallback_decode(data: &mut &[u8]) -> alloy_eips::eip2718::Eip2718Result<Self> {
        Self::decode(data).map_err(alloy_eips::eip2718::Eip2718Error::RlpError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_tx() -> TxEip8141 {
        TxEip8141 {
            chain_id: 8141,
            nonce: 0,
            sender: Address::ZERO,
            frames: vec![
                Frame {
                    mode: FrameMode::Verify as u8,
                    target: Some(Address::ZERO),
                    gas_limit: 100_000,
                    data: Bytes::from_static(&[0x01, 0x02, 0x03]),
                },
                Frame {
                    mode: FrameMode::Sender as u8,
                    target: Some(Address::ZERO),
                    gas_limit: 200_000,
                    data: Bytes::from_static(&[0xaa, 0xbb]),
                },
            ],
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 30_000_000_000,
            max_fee_per_blob_gas: 0,
            blob_versioned_hashes: vec![],
        }
    }

    #[test]
    fn test_rlp_roundtrip() {
        let tx = sample_tx();
        let mut buf = Vec::new();
        tx.encode(&mut buf);
        let decoded = TxEip8141::decode(&mut buf.as_slice()).unwrap();
        assert_eq!(tx, decoded);
    }

    #[test]
    fn test_signature_hash_zeroes_verify_data() {
        let tx = sample_tx();
        let sig_hash = tx.signature_hash();

        let mut tx2 = tx.clone();
        tx2.frames[0].data = Bytes::from_static(&[0xff, 0xfe, 0xfd]);
        assert_eq!(sig_hash, tx2.signature_hash());

        let mut tx3 = tx.clone();
        tx3.frames[1].data = Bytes::from_static(&[0xff]);
        assert_ne!(sig_hash, tx3.signature_hash());
    }

    #[test]
    fn test_total_gas_limit() {
        let tx = sample_tx();
        let expected = FRAME_TX_INTRINSIC_COST + 100_000 + 200_000 + tx.frames_calldata_cost();
        assert_eq!(tx.total_gas_limit(), expected);
    }

    #[test]
    fn test_2718_roundtrip() {
        use alloy_eips::eip2718::{Decodable2718, Encodable2718};

        let tx = sample_tx();
        let mut buf = Vec::new();
        tx.encode_2718(&mut buf);
        assert_eq!(buf[0], EIP8141_TX_TYPE_ID);

        let decoded = TxEip8141::decode_2718(&mut buf.as_slice()).unwrap();
        assert_eq!(tx, decoded);
    }

    // ─── Validation Tests ──────────────────────────────────────────────────

    #[test]
    fn test_validate_empty_frames() {
        let mut tx = sample_tx();
        tx.frames.clear();
        assert_eq!(tx.validate(), Err(Eip8141ValidationError::NoFrames));
    }

    #[test]
    fn test_validate_too_many_frames() {
        let mut tx = sample_tx();
        tx.frames = (0..MAX_FRAMES + 1)
            .map(|_| Frame {
                mode: FrameMode::Default as u8,
                target: Some(Address::ZERO),
                gas_limit: 1,
                data: Bytes::new(),
            })
            .collect();
        assert_eq!(
            tx.validate(),
            Err(Eip8141ValidationError::TooManyFrames { count: MAX_FRAMES + 1, max: MAX_FRAMES })
        );
    }

    #[test]
    fn test_validate_invalid_mode() {
        let mut tx = sample_tx();
        tx.frames[0].mode = 99;
        assert_eq!(
            tx.validate(),
            Err(Eip8141ValidationError::InvalidFrameMode { index: 0, mode: 99 })
        );
    }

    #[test]
    fn test_validate_gas_overflow() {
        let mut tx = sample_tx();
        tx.frames[0].gas_limit = u64::MAX;
        tx.frames[1].gas_limit = u64::MAX;
        assert_eq!(tx.validate(), Err(Eip8141ValidationError::GasLimitOverflow));
    }

    #[test]
    fn test_validate_verify_after_execution_allowed() {
        let mut tx = sample_tx();
        tx.frames.push(Frame {
            mode: FrameMode::Verify as u8,
            target: Some(Address::ZERO),
            gas_limit: 100,
            data: Bytes::new(),
        });
        assert!(tx.validate().is_ok());
    }

    #[test]
    fn test_validate_fee_invariant() {
        let mut tx = sample_tx();
        tx.max_fee_per_gas = 1;
        tx.max_priority_fee_per_gas = 100;
        assert_eq!(tx.validate(), Err(Eip8141ValidationError::MaxFeeBelowPriority));
    }

    #[test]
    fn test_validate_valid_tx() {
        let tx = sample_tx();
        assert!(tx.validate().is_ok());
    }

    // ─── Additional Unit Tests ─────────────────────────────────────────────

    #[test]
    fn test_frame_mode_from_u8_all_valid() {
        assert_eq!(FrameMode::from_u8(0), Some(FrameMode::Default));
        assert_eq!(FrameMode::from_u8(1), Some(FrameMode::Verify));
        assert_eq!(FrameMode::from_u8(2), Some(FrameMode::Sender));
    }

    #[test]
    fn test_frame_mode_from_u8_invalid() {
        assert_eq!(FrameMode::from_u8(3), None);
        assert_eq!(FrameMode::from_u8(255), None);
    }

    #[test]
    fn test_tx_hash_deterministic() {
        let tx = sample_tx();
        let hash1 = tx.tx_hash();
        let hash2 = tx.tx_hash();
        assert_eq!(hash1, hash2);

        // Different tx should produce different hash
        let mut tx2 = sample_tx();
        tx2.nonce = 42;
        assert_ne!(tx.tx_hash(), tx2.tx_hash());
    }

    #[test]
    fn test_decode_rejects_invalid_frames() {
        use alloy_eips::eip2718::Decodable2718;

        // Build a tx with no frames, encode it raw (bypassing validation)
        let tx = TxEip8141 {
            chain_id: 8141,
            nonce: 0,
            sender: Address::ZERO,
            frames: vec![],
            max_priority_fee_per_gas: 1,
            max_fee_per_gas: 10,
            max_fee_per_blob_gas: 0,
            blob_versioned_hashes: vec![],
        };
        let mut buf = Vec::new();
        // Manually encode with type prefix (bypass Encodable2718 which calls validate)
        buf.push(EIP8141_TX_TYPE_ID);
        tx.encode(&mut buf);

        // Decoding should fail validation
        assert!(TxEip8141::decode_2718(&mut buf.as_slice()).is_err());
    }

    #[test]
    fn test_null_target_roundtrip() {
        let mut tx = sample_tx();
        tx.frames[0].target = None;
        tx.frames[1].target = None;

        let mut buf = Vec::new();
        tx.encode(&mut buf);
        let decoded = TxEip8141::decode(&mut buf.as_slice()).unwrap();
        assert_eq!(decoded.frames[0].target, None);
        assert_eq!(decoded.frames[1].target, None);
        assert_eq!(decoded, tx);
    }
}
