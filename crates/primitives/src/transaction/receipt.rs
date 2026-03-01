use alloy_consensus::{
    Eip658Value, Receipt, ReceiptEnvelope, ReceiptWithBloom, RlpDecodableReceipt,
    RlpEncodableReceipt, TxReceipt, Typed2718,
};
use alloy_network::eip2718::{
    Decodable2718, EIP1559_TX_TYPE_ID, EIP2930_TX_TYPE_ID, EIP4844_TX_TYPE_ID, EIP7702_TX_TYPE_ID,
    Eip2718Error, Encodable2718, LEGACY_TX_TYPE_ID,
};
use alloy_primitives::{Address, Bloom, Log, TxHash, logs_bloom};
use alloy_rlp::{BufMut, Decodable, Encodable, Header, bytes};
use alloy_rpc_types::{BlockNumHash, trace::otterscan::OtsReceipt};
use op_alloy_consensus::{DEPOSIT_TX_TYPE_ID, OpDepositReceipt, OpDepositReceiptWithBloom};
use serde::{Deserialize, Serialize};
use tempo_primitives::TEMPO_TX_TYPE_ID;

use super::eip8141::EIP8141_TX_TYPE_ID;
use crate::FoundryTxType;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum FoundryReceiptEnvelope<T = Log> {
    #[serde(rename = "0x0", alias = "0x00")]
    Legacy(ReceiptWithBloom<Receipt<T>>),
    #[serde(rename = "0x1", alias = "0x01")]
    Eip2930(ReceiptWithBloom<Receipt<T>>),
    #[serde(rename = "0x2", alias = "0x02")]
    Eip1559(ReceiptWithBloom<Receipt<T>>),
    #[serde(rename = "0x3", alias = "0x03")]
    Eip4844(ReceiptWithBloom<Receipt<T>>),
    #[serde(rename = "0x4", alias = "0x04")]
    Eip7702(ReceiptWithBloom<Receipt<T>>),
    #[serde(rename = "0x7E", alias = "0x7e")]
    Deposit(OpDepositReceiptWithBloom<T>),
    #[serde(rename = "0x76")]
    Tempo(ReceiptWithBloom<Receipt<T>>),
    #[serde(rename = "0x6", alias = "0x06")]
    Eip8141(Eip8141ReceiptWithBloom<T>),
}

/// [`Eip8141Receipt`] with calculated bloom filter.
pub type Eip8141ReceiptWithBloom<T = Log> = ReceiptWithBloom<Eip8141Receipt<T>>;

/// EIP-8141 receipt payload extension.
///
/// ## RLP Wire Format (v2, current)
///
/// The `payer` field is always encoded:
/// - `Some(addr)` → 21-byte RLP address
/// - `None` → `0x80` (RLP empty string)
///
/// The decoder supports **both** v1 (payer omitted when None) and v2 (payer always present)
/// for backward-compatible reads. However, v1 binaries cannot decode v2 receipts where
/// `payer=None` (they will see an unexpected `0x80` byte). This is acceptable because
/// EIP-8141 is pre-mainnet and no v1 receipts exist in production.
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Eip8141Receipt<T = Log> {
    /// Canonical EVM receipt fields.
    #[serde(flatten)]
    pub inner: Receipt<T>,
    /// Approved payer selected by APPROVE.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payer: Option<Address>,
    /// Per-frame receipts (`null`=not executed, `false`=failed, `true`=success).
    #[serde(default, skip_serializing_if = "Eip8141FrameReceipts::is_empty")]
    pub frame_receipts: Eip8141FrameReceipts,
}

/// Per-frame statuses for EIP-8141 receipts.
///
/// We encode statuses as integer codes in RLP to avoid `Option<bool>` ambiguity:
/// `0 = null`, `1 = false`, `2 = true`.
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Eip8141FrameReceipts(pub Vec<Option<bool>>);

impl Eip8141FrameReceipts {
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    const fn status_code(status: Option<bool>) -> u8 {
        match status {
            None => 0,
            Some(false) => 1,
            Some(true) => 2,
        }
    }

    const fn decode_status_code(code: u8) -> Option<Option<bool>> {
        match code {
            0 => Some(None),
            1 => Some(Some(false)),
            2 => Some(Some(true)),
            _ => None,
        }
    }
}

impl Encodable for Eip8141FrameReceipts {
    fn encode(&self, out: &mut dyn bytes::BufMut) {
        let payload_length = self.0.iter().map(|s| Self::status_code(*s).length()).sum();
        Header { list: true, payload_length }.encode(out);
        for status in &self.0 {
            Self::status_code(*status).encode(out);
        }
    }

    fn length(&self) -> usize {
        let payload_length = self.0.iter().map(|s| Self::status_code(*s).length()).sum();
        Header { list: true, payload_length }.length_with_payload()
    }
}

impl Decodable for Eip8141FrameReceipts {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        use bytes::Buf;

        let header = Header::decode(buf)?;
        if !header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }

        if buf.len() < header.payload_length {
            return Err(alloy_rlp::Error::InputTooShort);
        }

        let mut fields_buf = &buf[..header.payload_length];
        let mut statuses = Vec::new();
        while !fields_buf.is_empty() {
            let code = u8::decode(&mut fields_buf)?;
            let status = Self::decode_status_code(code)
                .ok_or(alloy_rlp::Error::Custom("invalid eip8141 frame receipt status code"))?;
            statuses.push(status);
        }
        buf.advance(header.payload_length);
        Ok(Self(statuses))
    }
}

impl Eip8141Receipt {
    /// Calculates [`Log`]'s bloom filter.
    pub fn bloom_slow(&self) -> Bloom {
        self.inner.logs.iter().collect()
    }

    /// Calculates bloom and returns [`Eip8141ReceiptWithBloom`].
    pub fn with_bloom(self) -> Eip8141ReceiptWithBloom {
        self.into()
    }
}

impl<T> Eip8141Receipt<T> {
    /// Maps the inner receipt value.
    pub fn map_inner<U, F>(self, f: F) -> Eip8141Receipt<U>
    where
        F: FnOnce(Receipt<T>) -> Receipt<U>,
    {
        Eip8141Receipt {
            inner: f(self.inner),
            payer: self.payer,
            frame_receipts: self.frame_receipts,
        }
    }

    /// Attaches bloom to this receipt.
    pub const fn with_bloom_unchecked(self, bloom: Bloom) -> ReceiptWithBloom<Self> {
        ReceiptWithBloom::new(self, bloom)
    }

    /// Consumes and returns the inner [`Receipt`].
    pub fn into_inner(self) -> Receipt<T> {
        self.inner
    }

    /// Converts log type by applying a function to each log.
    pub fn map_logs<U>(self, f: impl FnMut(T) -> U) -> Eip8141Receipt<U> {
        self.map_inner(|r| r.map_logs(f))
    }
}

impl<T: Encodable> Eip8141Receipt<T> {
    /// Returns length of RLP-encoded receipt fields with bloom, without list header.
    pub fn rlp_encoded_fields_length_with_bloom(&self, bloom: &Bloom) -> usize {
        self.inner.rlp_encoded_fields_length_with_bloom(bloom)
            // Payer: always encoded — 21 bytes for Some(addr), 1 byte for None (0x80 empty string)
            + self.payer.map_or(1, |payer| payer.length())
            + self.frame_receipts.length()
    }

    /// RLP-encodes receipt fields with bloom, without list header.
    pub fn rlp_encode_fields_with_bloom(&self, bloom: &Bloom, out: &mut dyn BufMut) {
        self.inner.rlp_encode_fields_with_bloom(bloom, out);
        match self.payer {
            Some(payer) => payer.encode(out),
            None => Header { list: false, payload_length: 0 }.encode(out), // 0x80 = empty string
        }
        self.frame_receipts.encode(out);
    }

    /// Returns RLP list header for this receipt with bloom.
    pub fn rlp_header_with_bloom(&self, bloom: &Bloom) -> Header {
        Header { list: true, payload_length: self.rlp_encoded_fields_length_with_bloom(bloom) }
    }
}

impl<T: Decodable> Eip8141Receipt<T> {
    /// RLP-decodes receipt fields with bloom, without list header.
    pub fn rlp_decode_fields_with_bloom(
        buf: &mut &[u8],
    ) -> alloy_rlp::Result<ReceiptWithBloom<Self>> {
        let ReceiptWithBloom { receipt: inner, logs_bloom } =
            Receipt::rlp_decode_fields_with_bloom(buf)?;

        let payer = if !buf.is_empty() {
            if buf[0] == 0x80 {
                // New format: explicit empty string = None
                let _ = Header::decode(buf)?; // consume the 0x80 byte
                None
            } else if buf[0] < alloy_rlp::EMPTY_LIST_CODE {
                // Old format OR new format with address: decode 20-byte address
                Some(Address::decode(buf)?)
            } else {
                // Next field is a list (frame_receipts) — old format, no payer
                None
            }
        } else {
            None
        };
        let frame_receipts =
            if !buf.is_empty() { Eip8141FrameReceipts::decode(buf)? } else { Default::default() };

        Ok(ReceiptWithBloom { logs_bloom, receipt: Self { inner, payer, frame_receipts } })
    }
}

impl<T> AsRef<Receipt<T>> for Eip8141Receipt<T> {
    fn as_ref(&self) -> &Receipt<T> {
        &self.inner
    }
}

impl<T> From<Eip8141Receipt<T>> for Receipt<T> {
    fn from(value: Eip8141Receipt<T>) -> Self {
        value.into_inner()
    }
}

impl<T> TxReceipt for Eip8141Receipt<T>
where
    T: AsRef<Log> + Clone + core::fmt::Debug + PartialEq + Eq + Send + Sync,
{
    type Log = T;

    fn status_or_post_state(&self) -> Eip658Value {
        self.inner.status_or_post_state()
    }

    fn status(&self) -> bool {
        self.inner.status()
    }

    fn bloom(&self) -> Bloom {
        self.inner.bloom_slow()
    }

    fn cumulative_gas_used(&self) -> u64 {
        self.inner.cumulative_gas_used()
    }

    fn logs(&self) -> &[Self::Log] {
        self.inner.logs()
    }
}

impl<T: Encodable> RlpEncodableReceipt for Eip8141Receipt<T> {
    fn rlp_encoded_length_with_bloom(&self, bloom: &Bloom) -> usize {
        self.rlp_header_with_bloom(bloom).length_with_payload()
    }

    fn rlp_encode_with_bloom(&self, bloom: &Bloom, out: &mut dyn BufMut) {
        self.rlp_header_with_bloom(bloom).encode(out);
        self.rlp_encode_fields_with_bloom(bloom, out);
    }
}

impl<T: Decodable> RlpDecodableReceipt for Eip8141Receipt<T> {
    fn rlp_decode_with_bloom(buf: &mut &[u8]) -> alloy_rlp::Result<ReceiptWithBloom<Self>> {
        let header = Header::decode(buf)?;
        if !header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }

        if buf.len() < header.payload_length {
            return Err(alloy_rlp::Error::InputTooShort);
        }

        let mut fields_buf = &buf[..header.payload_length];
        let this = Self::rlp_decode_fields_with_bloom(&mut fields_buf)?;

        if !fields_buf.is_empty() {
            return Err(alloy_rlp::Error::ListLengthMismatch {
                expected: header.payload_length,
                got: header.payload_length - fields_buf.len(),
            });
        }

        use bytes::Buf;
        buf.advance(header.payload_length);
        Ok(this)
    }
}

impl FoundryReceiptEnvelope<alloy_rpc_types::Log> {
    /// Creates a new [`FoundryReceiptEnvelope`] from the given parts.
    pub fn from_parts(
        status: bool,
        cumulative_gas_used: u64,
        logs: impl IntoIterator<Item = alloy_rpc_types::Log>,
        tx_type: FoundryTxType,
        deposit_nonce: Option<u64>,
        deposit_receipt_version: Option<u64>,
    ) -> Self {
        Self::from_parts_with_eip8141(
            status,
            cumulative_gas_used,
            logs,
            tx_type,
            deposit_nonce,
            deposit_receipt_version,
            None,
            None,
        )
    }

    /// Creates a new [`FoundryReceiptEnvelope`] from parts and optional EIP-8141 payload fields.
    pub fn from_parts_with_eip8141(
        status: bool,
        cumulative_gas_used: u64,
        logs: impl IntoIterator<Item = alloy_rpc_types::Log>,
        tx_type: FoundryTxType,
        deposit_nonce: Option<u64>,
        deposit_receipt_version: Option<u64>,
        eip8141_payer: Option<Address>,
        eip8141_frame_receipts: Option<Vec<Option<bool>>>,
    ) -> Self {
        let logs = logs.into_iter().collect::<Vec<_>>();
        let logs_bloom = logs_bloom(logs.iter().map(|l| &l.inner));
        let inner_receipt =
            Receipt { status: Eip658Value::Eip658(status), cumulative_gas_used, logs };
        match tx_type {
            FoundryTxType::Legacy => {
                Self::Legacy(ReceiptWithBloom { receipt: inner_receipt, logs_bloom })
            }
            FoundryTxType::Eip2930 => {
                Self::Eip2930(ReceiptWithBloom { receipt: inner_receipt, logs_bloom })
            }
            FoundryTxType::Eip1559 => {
                Self::Eip1559(ReceiptWithBloom { receipt: inner_receipt, logs_bloom })
            }
            FoundryTxType::Eip4844 => {
                Self::Eip4844(ReceiptWithBloom { receipt: inner_receipt, logs_bloom })
            }
            FoundryTxType::Eip7702 => {
                Self::Eip7702(ReceiptWithBloom { receipt: inner_receipt, logs_bloom })
            }
            FoundryTxType::Deposit => {
                let inner = OpDepositReceiptWithBloom {
                    receipt: OpDepositReceipt {
                        inner: inner_receipt,
                        deposit_nonce,
                        deposit_receipt_version,
                    },
                    logs_bloom,
                };
                Self::Deposit(inner)
            }
            FoundryTxType::Tempo => {
                Self::Tempo(ReceiptWithBloom { receipt: inner_receipt, logs_bloom })
            }
            FoundryTxType::Eip8141 => Self::Eip8141(Eip8141ReceiptWithBloom {
                receipt: Eip8141Receipt {
                    inner: inner_receipt,
                    payer: eip8141_payer,
                    frame_receipts: Eip8141FrameReceipts(
                        eip8141_frame_receipts.unwrap_or_default(),
                    ),
                },
                logs_bloom,
            }),
        }
    }
}

impl FoundryReceiptEnvelope<Log> {
    pub fn convert_logs_rpc(
        self,
        block_numhash: BlockNumHash,
        block_timestamp: u64,
        transaction_hash: TxHash,
        transaction_index: u64,
        next_log_index: usize,
    ) -> FoundryReceiptEnvelope<alloy_rpc_types::Log> {
        let logs = self
            .logs()
            .iter()
            .enumerate()
            .map(|(index, log)| alloy_rpc_types::Log {
                inner: log.clone(),
                block_hash: Some(block_numhash.hash),
                block_number: Some(block_numhash.number),
                block_timestamp: Some(block_timestamp),
                transaction_hash: Some(transaction_hash),
                transaction_index: Some(transaction_index),
                log_index: Some((next_log_index + index) as u64),
                removed: false,
            })
            .collect::<Vec<_>>();
        let (eip8141_payer, eip8141_frame_receipts) = match &self {
            Self::Eip8141(receipt) => {
                (receipt.receipt.payer, Some(receipt.receipt.frame_receipts.0.clone()))
            }
            _ => (None, None),
        };
        FoundryReceiptEnvelope::<alloy_rpc_types::Log>::from_parts_with_eip8141(
            self.status(),
            self.cumulative_gas_used(),
            logs,
            self.tx_type(),
            self.deposit_nonce(),
            self.deposit_receipt_version(),
            eip8141_payer,
            eip8141_frame_receipts,
        )
    }
}

impl<T> FoundryReceiptEnvelope<T> {
    /// Return the [`FoundryTxType`] of the inner receipt.
    pub const fn tx_type(&self) -> FoundryTxType {
        match self {
            Self::Legacy(_) => FoundryTxType::Legacy,
            Self::Eip2930(_) => FoundryTxType::Eip2930,
            Self::Eip1559(_) => FoundryTxType::Eip1559,
            Self::Eip4844(_) => FoundryTxType::Eip4844,
            Self::Eip7702(_) => FoundryTxType::Eip7702,
            Self::Deposit(_) => FoundryTxType::Deposit,
            Self::Tempo(_) => FoundryTxType::Tempo,
            Self::Eip8141(_) => FoundryTxType::Eip8141,
        }
    }

    /// Returns the success status of the receipt's transaction.
    pub const fn status(&self) -> bool {
        self.as_receipt().status.coerce_status()
    }

    /// Returns the cumulative gas used at this receipt.
    pub const fn cumulative_gas_used(&self) -> u64 {
        self.as_receipt().cumulative_gas_used
    }

    /// Converts the receipt's log type by applying a function to each log.
    ///
    /// Returns the receipt with the new log type.
    pub fn map_logs<U>(self, f: impl FnMut(T) -> U) -> FoundryReceiptEnvelope<U> {
        match self {
            Self::Legacy(r) => FoundryReceiptEnvelope::Legacy(r.map_logs(f)),
            Self::Eip2930(r) => FoundryReceiptEnvelope::Eip2930(r.map_logs(f)),
            Self::Eip1559(r) => FoundryReceiptEnvelope::Eip1559(r.map_logs(f)),
            Self::Eip4844(r) => FoundryReceiptEnvelope::Eip4844(r.map_logs(f)),
            Self::Eip7702(r) => FoundryReceiptEnvelope::Eip7702(r.map_logs(f)),
            Self::Deposit(r) => FoundryReceiptEnvelope::Deposit(r.map_receipt(|r| r.map_logs(f))),
            Self::Tempo(r) => FoundryReceiptEnvelope::Tempo(r.map_logs(f)),
            Self::Eip8141(r) => FoundryReceiptEnvelope::Eip8141(r.map_receipt(|r| r.map_logs(f))),
        }
    }

    /// Return the receipt logs.
    pub fn logs(&self) -> &[T] {
        &self.as_receipt().logs
    }

    /// Consumes the type and returns the logs.
    pub fn into_logs(self) -> Vec<T> {
        self.into_receipt().logs
    }

    /// Return the receipt's bloom.
    pub const fn logs_bloom(&self) -> &Bloom {
        match self {
            Self::Legacy(t) => &t.logs_bloom,
            Self::Eip2930(t) => &t.logs_bloom,
            Self::Eip1559(t) => &t.logs_bloom,
            Self::Eip4844(t) => &t.logs_bloom,
            Self::Eip7702(t) => &t.logs_bloom,
            Self::Deposit(t) => &t.logs_bloom,
            Self::Tempo(t) => &t.logs_bloom,
            Self::Eip8141(t) => &t.logs_bloom,
        }
    }

    /// Return the receipt's deposit_nonce if it is a deposit receipt.
    pub fn deposit_nonce(&self) -> Option<u64> {
        self.as_deposit_receipt().and_then(|r| r.deposit_nonce)
    }

    /// Return the receipt's deposit version if it is a deposit receipt.
    pub fn deposit_receipt_version(&self) -> Option<u64> {
        self.as_deposit_receipt().and_then(|r| r.deposit_receipt_version)
    }

    /// Return the EIP-8141 payer if this is an EIP-8141 receipt.
    pub fn payer(&self) -> Option<Address> {
        match self {
            Self::Eip8141(t) => t.receipt.payer,
            _ => None,
        }
    }

    /// Return the EIP-8141 per-frame statuses if this is an EIP-8141 receipt.
    pub fn frame_receipts(&self) -> Option<&[Option<bool>]> {
        match self {
            Self::Eip8141(t) => Some(&t.receipt.frame_receipts.0),
            _ => None,
        }
    }

    /// Returns the deposit receipt if it is a deposit receipt.
    pub const fn as_deposit_receipt_with_bloom(&self) -> Option<&OpDepositReceiptWithBloom<T>> {
        match self {
            Self::Deposit(t) => Some(t),
            _ => None,
        }
    }

    /// Returns the deposit receipt if it is a deposit receipt.
    pub const fn as_deposit_receipt(&self) -> Option<&OpDepositReceipt<T>> {
        match self {
            Self::Deposit(t) => Some(&t.receipt),
            _ => None,
        }
    }

    /// Consumes the type and returns the underlying [`Receipt`].
    pub fn into_receipt(self) -> Receipt<T> {
        match self {
            Self::Legacy(t)
            | Self::Eip2930(t)
            | Self::Eip1559(t)
            | Self::Eip4844(t)
            | Self::Eip7702(t)
            | Self::Tempo(t) => t.receipt,
            Self::Eip8141(t) => t.receipt.inner,
            Self::Deposit(t) => t.receipt.into_inner(),
        }
    }

    /// Return the inner receipt.
    pub const fn as_receipt(&self) -> &Receipt<T> {
        match self {
            Self::Legacy(t)
            | Self::Eip2930(t)
            | Self::Eip1559(t)
            | Self::Eip4844(t)
            | Self::Eip7702(t)
            | Self::Tempo(t) => &t.receipt,
            Self::Eip8141(t) => &t.receipt.inner,
            Self::Deposit(t) => &t.receipt.inner,
        }
    }
}

impl<T> TxReceipt for FoundryReceiptEnvelope<T>
where
    T: Clone + core::fmt::Debug + PartialEq + Eq + Send + Sync,
{
    type Log = T;

    fn status_or_post_state(&self) -> Eip658Value {
        self.as_receipt().status
    }

    fn status(&self) -> bool {
        self.status()
    }

    /// Return the receipt's bloom.
    fn bloom(&self) -> Bloom {
        *self.logs_bloom()
    }

    fn bloom_cheap(&self) -> Option<Bloom> {
        Some(self.bloom())
    }

    /// Returns the cumulative gas used at this receipt.
    fn cumulative_gas_used(&self) -> u64 {
        self.cumulative_gas_used()
    }

    /// Return the receipt logs.
    fn logs(&self) -> &[T] {
        self.logs()
    }
}

impl Encodable for FoundryReceiptEnvelope {
    fn encode(&self, out: &mut dyn bytes::BufMut) {
        match self {
            Self::Legacy(r) => r.encode(out),
            receipt => {
                let payload_len = match receipt {
                    Self::Eip2930(r) => r.length() + 1,
                    Self::Eip1559(r) => r.length() + 1,
                    Self::Eip4844(r) => r.length() + 1,
                    Self::Eip7702(r) => r.length() + 1,
                    Self::Deposit(r) => r.length() + 1,
                    Self::Tempo(r) => r.length() + 1,
                    Self::Eip8141(r) => r.length() + 1,
                    _ => unreachable!("receipt already matched"),
                };

                match receipt {
                    Self::Eip2930(r) => {
                        Header { list: true, payload_length: payload_len }.encode(out);
                        EIP2930_TX_TYPE_ID.encode(out);
                        r.encode(out);
                    }
                    Self::Eip1559(r) => {
                        Header { list: true, payload_length: payload_len }.encode(out);
                        EIP1559_TX_TYPE_ID.encode(out);
                        r.encode(out);
                    }
                    Self::Eip4844(r) => {
                        Header { list: true, payload_length: payload_len }.encode(out);
                        EIP4844_TX_TYPE_ID.encode(out);
                        r.encode(out);
                    }
                    Self::Eip7702(r) => {
                        Header { list: true, payload_length: payload_len }.encode(out);
                        EIP7702_TX_TYPE_ID.encode(out);
                        r.encode(out);
                    }
                    Self::Deposit(r) => {
                        Header { list: true, payload_length: payload_len }.encode(out);
                        DEPOSIT_TX_TYPE_ID.encode(out);
                        r.encode(out);
                    }
                    Self::Tempo(r) => {
                        Header { list: true, payload_length: payload_len }.encode(out);
                        TEMPO_TX_TYPE_ID.encode(out);
                        r.encode(out);
                    }
                    Self::Eip8141(r) => {
                        Header { list: true, payload_length: payload_len }.encode(out);
                        EIP8141_TX_TYPE_ID.encode(out);
                        r.encode(out);
                    }
                    _ => unreachable!("receipt already matched"),
                }
            }
        }
    }
}

impl Decodable for FoundryReceiptEnvelope {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        use bytes::Buf;
        use std::cmp::Ordering;

        // a receipt is either encoded as a string (non legacy) or a list (legacy).
        // We should not consume the buffer if we are decoding a legacy receipt, so let's
        // check if the first byte is between 0x80 and 0xbf.
        let rlp_type = *buf
            .first()
            .ok_or(alloy_rlp::Error::Custom("cannot decode a receipt from empty bytes"))?;

        match rlp_type.cmp(&alloy_rlp::EMPTY_LIST_CODE) {
            Ordering::Less => {
                // strip out the string header
                let _header = Header::decode(buf)?;
                let receipt_type = *buf.first().ok_or(alloy_rlp::Error::Custom(
                    "typed receipt cannot be decoded from an empty slice",
                ))?;
                if receipt_type == EIP2930_TX_TYPE_ID {
                    buf.advance(1);
                    <ReceiptWithBloom as Decodable>::decode(buf)
                        .map(FoundryReceiptEnvelope::Eip2930)
                } else if receipt_type == EIP1559_TX_TYPE_ID {
                    buf.advance(1);
                    <ReceiptWithBloom as Decodable>::decode(buf)
                        .map(FoundryReceiptEnvelope::Eip1559)
                } else if receipt_type == EIP4844_TX_TYPE_ID {
                    buf.advance(1);
                    <ReceiptWithBloom as Decodable>::decode(buf)
                        .map(FoundryReceiptEnvelope::Eip4844)
                } else if receipt_type == EIP7702_TX_TYPE_ID {
                    buf.advance(1);
                    <ReceiptWithBloom as Decodable>::decode(buf)
                        .map(FoundryReceiptEnvelope::Eip7702)
                } else if receipt_type == DEPOSIT_TX_TYPE_ID {
                    buf.advance(1);
                    <OpDepositReceiptWithBloom as Decodable>::decode(buf)
                        .map(FoundryReceiptEnvelope::Deposit)
                } else if receipt_type == TEMPO_TX_TYPE_ID {
                    buf.advance(1);
                    <ReceiptWithBloom as Decodable>::decode(buf).map(FoundryReceiptEnvelope::Tempo)
                } else if receipt_type == EIP8141_TX_TYPE_ID {
                    buf.advance(1);
                    <Eip8141ReceiptWithBloom as Decodable>::decode(buf)
                        .map(FoundryReceiptEnvelope::Eip8141)
                } else {
                    Err(alloy_rlp::Error::Custom("invalid receipt type"))
                }
            }
            Ordering::Equal => {
                Err(alloy_rlp::Error::Custom("an empty list is not a valid receipt encoding"))
            }
            Ordering::Greater => {
                <ReceiptWithBloom as Decodable>::decode(buf).map(FoundryReceiptEnvelope::Legacy)
            }
        }
    }
}

impl Typed2718 for FoundryReceiptEnvelope {
    fn ty(&self) -> u8 {
        match self {
            Self::Legacy(_) => LEGACY_TX_TYPE_ID,
            Self::Eip2930(_) => EIP2930_TX_TYPE_ID,
            Self::Eip1559(_) => EIP1559_TX_TYPE_ID,
            Self::Eip4844(_) => EIP4844_TX_TYPE_ID,
            Self::Eip7702(_) => EIP7702_TX_TYPE_ID,
            Self::Deposit(_) => DEPOSIT_TX_TYPE_ID,
            Self::Tempo(_) => TEMPO_TX_TYPE_ID,
            Self::Eip8141(_) => EIP8141_TX_TYPE_ID,
        }
    }
}

impl Encodable2718 for FoundryReceiptEnvelope {
    fn encode_2718_len(&self) -> usize {
        match self {
            Self::Legacy(r) => r.length(),
            Self::Eip2930(r) => 1 + r.length(),
            Self::Eip1559(r) => 1 + r.length(),
            Self::Eip4844(r) => 1 + r.length(),
            Self::Eip7702(r) => 1 + r.length(),
            Self::Deposit(r) => 1 + r.length(),
            Self::Tempo(r) => 1 + r.length(),
            Self::Eip8141(r) => 1 + r.length(),
        }
    }

    fn encode_2718(&self, out: &mut dyn BufMut) {
        if let Some(ty) = self.type_flag() {
            out.put_u8(ty);
        }
        match self {
            Self::Legacy(r)
            | Self::Eip2930(r)
            | Self::Eip1559(r)
            | Self::Eip4844(r)
            | Self::Eip7702(r)
            | Self::Tempo(r) => r.encode(out),
            Self::Eip8141(r) => r.encode(out),
            Self::Deposit(r) => r.encode(out),
        }
    }
}

impl Decodable2718 for FoundryReceiptEnvelope {
    fn typed_decode(ty: u8, buf: &mut &[u8]) -> Result<Self, Eip2718Error> {
        if ty == DEPOSIT_TX_TYPE_ID {
            return Ok(Self::Deposit(OpDepositReceiptWithBloom::decode(buf)?));
        }
        if ty == TEMPO_TX_TYPE_ID {
            return Ok(Self::Tempo(ReceiptWithBloom::decode(buf)?));
        }
        if ty == EIP8141_TX_TYPE_ID {
            return Ok(Self::Eip8141(Eip8141ReceiptWithBloom::decode(buf)?));
        }
        match ReceiptEnvelope::typed_decode(ty, buf)? {
            ReceiptEnvelope::Eip2930(tx) => Ok(Self::Eip2930(tx)),
            ReceiptEnvelope::Eip1559(tx) => Ok(Self::Eip1559(tx)),
            ReceiptEnvelope::Eip4844(tx) => Ok(Self::Eip4844(tx)),
            ReceiptEnvelope::Eip7702(tx) => Ok(Self::Eip7702(tx)),
            _ => Err(Eip2718Error::RlpError(alloy_rlp::Error::Custom("unexpected tx type"))),
        }
    }

    fn fallback_decode(buf: &mut &[u8]) -> Result<Self, Eip2718Error> {
        match ReceiptEnvelope::fallback_decode(buf)? {
            ReceiptEnvelope::Legacy(tx) => Ok(Self::Legacy(tx)),
            _ => Err(Eip2718Error::RlpError(alloy_rlp::Error::Custom("unexpected tx type"))),
        }
    }
}

impl From<FoundryReceiptEnvelope<alloy_rpc_types::Log>> for OtsReceipt {
    fn from(receipt: FoundryReceiptEnvelope<alloy_rpc_types::Log>) -> Self {
        Self {
            status: receipt.status(),
            cumulative_gas_used: receipt.cumulative_gas_used(),
            logs: Some(receipt.logs().to_vec()),
            logs_bloom: Some(receipt.logs_bloom().to_owned()),
            r#type: receipt.tx_type() as u8,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{B256, Bytes, LogData, address, hex};
    use std::str::FromStr;

    #[test]
    fn encode_legacy_receipt() {
        let expected = hex::decode("f901668001b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f85ff85d940000000000000000000000000000000000000011f842a0000000000000000000000000000000000000000000000000000000000000deada0000000000000000000000000000000000000000000000000000000000000beef830100ff").unwrap();

        let mut data = vec![];
        let receipt = FoundryReceiptEnvelope::Legacy(ReceiptWithBloom {
            receipt: Receipt {
                status: false.into(),
                cumulative_gas_used: 0x1,
                logs: vec![Log {
                    address: Address::from_str("0000000000000000000000000000000000000011").unwrap(),
                    data: LogData::new_unchecked(
                        vec![
                            B256::from_str(
                                "000000000000000000000000000000000000000000000000000000000000dead",
                            )
                            .unwrap(),
                            B256::from_str(
                                "000000000000000000000000000000000000000000000000000000000000beef",
                            )
                            .unwrap(),
                        ],
                        Bytes::from_str("0100ff").unwrap(),
                    ),
                }],
            },
            logs_bloom: [0; 256].into(),
        });

        receipt.encode(&mut data);

        // check that the rlp length equals the length of the expected rlp
        assert_eq!(receipt.length(), expected.len());
        assert_eq!(data, expected);
    }

    #[test]
    fn decode_legacy_receipt() {
        let data = hex::decode("f901668001b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f85ff85d940000000000000000000000000000000000000011f842a0000000000000000000000000000000000000000000000000000000000000deada0000000000000000000000000000000000000000000000000000000000000beef830100ff").unwrap();

        let expected = FoundryReceiptEnvelope::Legacy(ReceiptWithBloom {
            receipt: Receipt {
                status: false.into(),
                cumulative_gas_used: 0x1,
                logs: vec![Log {
                    address: Address::from_str("0000000000000000000000000000000000000011").unwrap(),
                    data: LogData::new_unchecked(
                        vec![
                            B256::from_str(
                                "000000000000000000000000000000000000000000000000000000000000dead",
                            )
                            .unwrap(),
                            B256::from_str(
                                "000000000000000000000000000000000000000000000000000000000000beef",
                            )
                            .unwrap(),
                        ],
                        Bytes::from_str("0100ff").unwrap(),
                    ),
                }],
            },
            logs_bloom: [0; 256].into(),
        });

        let receipt = FoundryReceiptEnvelope::decode(&mut &data[..]).unwrap();

        assert_eq!(receipt, expected);
    }

    #[test]
    fn encode_tempo_receipt() {
        use alloy_network::eip2718::Encodable2718;
        use tempo_primitives::TEMPO_TX_TYPE_ID;

        let receipt = FoundryReceiptEnvelope::Tempo(ReceiptWithBloom {
            receipt: Receipt {
                status: true.into(),
                cumulative_gas_used: 157716,
                logs: vec![Log {
                    address: Address::from_str("20c0000000000000000000000000000000000000").unwrap(),
                    data: LogData::new_unchecked(
                        vec![
                            B256::from_str(
                                "8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925",
                            )
                            .unwrap(),
                            B256::from_str(
                                "000000000000000000000000566ff0f4a6114f8072ecdc8a7a8a13d8d0c6b45f",
                            )
                            .unwrap(),
                            B256::from_str(
                                "000000000000000000000000dec0000000000000000000000000000000000000",
                            )
                            .unwrap(),
                        ],
                        Bytes::from_str(
                            "0000000000000000000000000000000000000000000000000000000000989680",
                        )
                        .unwrap(),
                    ),
                }],
            },
            logs_bloom: [0; 256].into(),
        });

        assert_eq!(receipt.tx_type(), FoundryTxType::Tempo);
        assert_eq!(receipt.ty(), TEMPO_TX_TYPE_ID);
        assert!(receipt.status());
        assert_eq!(receipt.cumulative_gas_used(), 157716);
        assert_eq!(receipt.logs().len(), 1);

        // Encode and decode round-trip
        let mut encoded = Vec::new();
        receipt.encode_2718(&mut encoded);

        // First byte should be the Tempo type ID
        assert_eq!(encoded[0], TEMPO_TX_TYPE_ID);

        // Decode it back
        let decoded = FoundryReceiptEnvelope::decode(&mut &encoded[..]).unwrap();
        assert_eq!(receipt, decoded);
    }

    #[test]
    fn decode_tempo_receipt() {
        use alloy_network::eip2718::Encodable2718;
        use tempo_primitives::TEMPO_TX_TYPE_ID;

        let receipt = FoundryReceiptEnvelope::Tempo(ReceiptWithBloom {
            receipt: Receipt { status: true.into(), cumulative_gas_used: 21000, logs: vec![] },
            logs_bloom: [0; 256].into(),
        });

        // Encode and decode via 2718
        let mut encoded = Vec::new();
        receipt.encode_2718(&mut encoded);
        assert_eq!(encoded[0], TEMPO_TX_TYPE_ID);

        use alloy_network::eip2718::Decodable2718;
        let decoded = FoundryReceiptEnvelope::decode_2718(&mut &encoded[..]).unwrap();
        assert_eq!(receipt, decoded);
    }

    #[test]
    fn tempo_receipt_from_parts() {
        let receipt = FoundryReceiptEnvelope::<alloy_rpc_types::Log>::from_parts(
            true,
            100000,
            vec![],
            FoundryTxType::Tempo,
            None,
            None,
        );

        assert_eq!(receipt.tx_type(), FoundryTxType::Tempo);
        assert!(receipt.status());
        assert_eq!(receipt.cumulative_gas_used(), 100000);
        assert!(receipt.logs().is_empty());
        assert!(receipt.deposit_nonce().is_none());
        assert!(receipt.deposit_receipt_version().is_none());
    }

    #[test]
    fn tempo_receipt_map_logs() {
        let receipt = FoundryReceiptEnvelope::Tempo(ReceiptWithBloom {
            receipt: Receipt {
                status: true.into(),
                cumulative_gas_used: 21000,
                logs: vec![Log {
                    address: Address::from_str("20c0000000000000000000000000000000000000").unwrap(),
                    data: LogData::new_unchecked(vec![], Bytes::default()),
                }],
            },
            logs_bloom: [0; 256].into(),
        });

        // Map logs to a different type (just clone in this case)
        let mapped = receipt.map_logs(|log| log);
        assert_eq!(mapped.logs().len(), 1);
        assert_eq!(mapped.tx_type(), FoundryTxType::Tempo);
    }

    #[test]
    fn eip8141_receipt_roundtrip_2718() {
        use alloy_network::eip2718::{Decodable2718, Encodable2718};

        let receipt = FoundryReceiptEnvelope::Eip8141(Eip8141ReceiptWithBloom {
            receipt: Eip8141Receipt {
                inner: Receipt {
                    status: true.into(),
                    cumulative_gas_used: 45678,
                    logs: vec![Log {
                        address: address!("0000000000000000000000000000000000000011"),
                        data: LogData::new_unchecked(vec![], Bytes::default()),
                    }],
                },
                payer: Some(address!("0000000000000000000000000000000000000022")),
                frame_receipts: Eip8141FrameReceipts(vec![Some(true), Some(false), None]),
            },
            logs_bloom: [0; 256].into(),
        });

        let mut encoded = Vec::new();
        receipt.encode_2718(&mut encoded);
        assert_eq!(encoded[0], EIP8141_TX_TYPE_ID);

        let decoded = FoundryReceiptEnvelope::decode_2718(&mut &encoded[..]).unwrap();
        assert_eq!(decoded, receipt);
        assert_eq!(
            decoded.frame_receipts(),
            Some(&[Some(true), Some(false), None] as &[Option<bool>]),
        );
        assert_eq!(decoded.payer(), Some(address!("0000000000000000000000000000000000000022")));
    }

    #[test]
    fn eip8141_receipt_backward_compat_decode_without_extension_fields() {
        use alloy_network::eip2718::Decodable2718;

        let mut encoded = vec![EIP8141_TX_TYPE_ID];
        let legacy_payload: ReceiptWithBloom<Receipt<Log>> = ReceiptWithBloom {
            receipt: Receipt { status: true.into(), cumulative_gas_used: 21000, logs: vec![] },
            logs_bloom: [0; 256].into(),
        };
        legacy_payload.encode(&mut encoded);

        let decoded = FoundryReceiptEnvelope::decode_2718(&mut &encoded[..]).unwrap();
        assert_eq!(decoded.tx_type(), FoundryTxType::Eip8141);
        assert_eq!(decoded.payer(), None);
        assert_eq!(decoded.frame_receipts(), Some([].as_slice()));
        assert_eq!(decoded.cumulative_gas_used(), 21000);
    }

    #[test]
    fn eip8141_frame_receipts_rlp_roundtrip() {
        let original = Eip8141FrameReceipts(vec![None, Some(false), Some(true), None]);
        let encoded = alloy_rlp::encode(&original);
        let decoded = Eip8141FrameReceipts::decode(&mut &encoded[..]).unwrap();
        assert_eq!(decoded, original);
    }

    /// ET3: Receipt payer encoding backward compatibility.
    /// New format always encodes payer (0x80 for None). Old format omits it entirely.
    /// Decoder must support both.
    #[test]
    fn eip8141_receipt_payer_encoding_compat() {
        use alloy_network::eip2718::{Decodable2718, Encodable2718};

        // New format roundtrip: payer=None (encoded as 0x80)
        let receipt_none = FoundryReceiptEnvelope::Eip8141(Eip8141ReceiptWithBloom {
            receipt: Eip8141Receipt {
                inner: Receipt { status: true.into(), cumulative_gas_used: 21000, logs: vec![] },
                payer: None,
                frame_receipts: Eip8141FrameReceipts(vec![Some(true)]),
            },
            logs_bloom: [0; 256].into(),
        });
        let mut encoded = Vec::new();
        receipt_none.encode_2718(&mut encoded);
        let decoded = FoundryReceiptEnvelope::decode_2718(&mut &encoded[..]).unwrap();
        assert_eq!(decoded.payer(), None);
        assert_eq!(decoded.frame_receipts(), Some(&[Some(true)] as &[Option<bool>]));

        // New format roundtrip: payer=Some(addr)
        let addr = address!("0000000000000000000000000000000000000033");
        let receipt_some = FoundryReceiptEnvelope::Eip8141(Eip8141ReceiptWithBloom {
            receipt: Eip8141Receipt {
                inner: Receipt { status: true.into(), cumulative_gas_used: 42000, logs: vec![] },
                payer: Some(addr),
                frame_receipts: Eip8141FrameReceipts(vec![Some(true), Some(false)]),
            },
            logs_bloom: [0; 256].into(),
        });
        let mut encoded = Vec::new();
        receipt_some.encode_2718(&mut encoded);
        let decoded = FoundryReceiptEnvelope::decode_2718(&mut &encoded[..]).unwrap();
        assert_eq!(decoded.payer(), Some(addr));

        // Old format: payer field omitted entirely (just inner receipt + frame_receipts list)
        // The old format backward compat test already exists above.
    }
}
