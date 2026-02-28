//! EIP-8141 frame transaction execution.
//!
//! Frame transactions (type 0x06) enable composable execution with
//! multiple frames. Each frame targets a contract with a specific mode:
//! - **VERIFY** (1): Must call APPROVE opcode to authorize the sender.
//! - **DEFAULT** (0): Executes from ENTRY_POINT after approval.
//! - **SENDER** (2): Executes from tx.sender after approval.
//!
//! No ECDSA signature — sender is explicit in the transaction.
//!
//! ## Execution Flow
//!
//! 1. Build a `FrameTxContext` from the transaction fields.
//! 2. Construct a separate `RevmEvm` with EIP-8141 opcodes enabled.
//! 3. Validate nonce and balance of the sender account.
//! 4. Iterate through frames in order:
//!    - VERIFY frames run first; they must call the APPROVE opcode.
//!    - Once approved, DEFAULT/SENDER frames execute with the appropriate caller.
//! 5. Refund unused gas to the sender after all frames complete.
//!
//! We use `Handler::execution()` directly for each frame — it runs the frame
//! and returns `FrameResult` WITHOUT calling `commit_tx()` or `finalize()`.
//! This preserves journal entries so checkpoint/revert works correctly,
//! and we control when to commit via a single `finalize()` + `commit()` at the end.

use super::env::Env;
use alloy_primitives::{Bytes, Log, U256};
use foundry_evm::backend::DatabaseError;
use foundry_primitives::{
    FrameMode, TxEip8141, ENTRY_POINT, FRAME_TX_INTRINSIC_COST,
};
use revm::{
    Database, DatabaseCommit, ExecuteCommitEvm, ExecuteEvm,
    context::{Evm as RevmEvm, Journal, TxEnv},
    context_interface::{
        JournalTr as _,
        LocalContextTr as _,
        journaled_state::account::JournaledAccountTr as _,
        result::{EVMError, ExecutionResult, Output, SuccessReason},
    },
    handler::{
        Handler as _, MainnetHandler,
        instructions::EthInstructions,
    },
    interpreter::{instructions::frame_tx::FrameTxContext, interpreter::EthInterpreter},
    interpreter::InitialAndFloorGas,
    precompile::{PrecompileSpecId, Precompiles},
};
use alloy_evm::precompiles::PrecompilesMap;
use std::fmt::Debug;

/// Builds a [`FrameTxContext`] from a [`TxEip8141`].
///
/// The context carries all frame-transaction metadata that the EIP-8141 opcodes
/// (TXPARAMLOAD, TXPARAMSIZE, TXPARAMCOPY, APPROVE) need at runtime.
fn build_frame_tx_context(tx: &TxEip8141) -> FrameTxContext {
    use revm::interpreter::instructions::frame_tx::FrameInfo;

    // VERIFY frame data is zeroed in the signature hash so that verifiers
    // commit to frame targets but not to verification data itself.
    let sig_hash = tx.signature_hash();

    FrameTxContext {
        active: true,
        sender_approved: false,
        payer_approved: false,
        sender: tx.sender,
        payer: tx.sender,
        tx_type: 0x06,
        nonce: tx.nonce,
        max_priority_fee_per_gas: tx.max_priority_fee_per_gas,
        max_fee_per_gas: tx.max_fee_per_gas,
        max_fee_per_blob_gas: tx.max_fee_per_blob_gas,
        max_cost: U256::from(tx.max_fee_per_gas) * U256::from(tx.total_gas_limit()),
        blob_versioned_hashes: tx.blob_versioned_hashes.clone(),
        sig_hash,
        frame_count: tx.frames.len(),
        current_frame_index: 0,
        frames: tx
            .frames
            .iter()
            .map(|f| FrameInfo {
                mode: f.mode,
                target: f.target,
                gas_limit: f.gas_limit,
                data: f.data.clone(),
                status: None,
            })
            .collect(),
    }
}

/// Executes an EIP-8141 frame transaction.
///
/// Creates a separate EVM with `FrameTxContext` as chain parameter and EIP-8141
/// opcodes enabled, then runs each frame in sequence. This bypasses the standard
/// `EitherEvm` path (which uses `chain: ()`) and instead constructs a raw
/// `RevmEvm` with the correct context type.
pub fn execute_eip8141_frame_tx<DB>(
    db: DB,
    env: &Env,
    frame_tx: &TxEip8141,
) -> Result<ExecutionResult, EVMError<DatabaseError>>
where
    DB: Database<Error = DatabaseError> + DatabaseCommit + Debug,
{
    let spec = env.evm_env.cfg_env.spec;
    let frame_ctx = build_frame_tx_context(frame_tx);

    // Build a Context with FrameTxContext as chain parameter.
    let mut cfg = env.evm_env.cfg_env.clone();
    cfg.spec = spec;

    let mut journal = Journal::new(db);
    journal.set_spec_id(spec);

    let ctx = revm::context::Context {
        block: env.evm_env.block_env.clone(),
        tx: TxEnv::default(),
        cfg,
        journaled_state: journal,
        chain: frame_ctx.clone(),
        local: revm::context::LocalContext::default(),
        error: Ok(()),
    };

    // Build EVM with EIP-8141 opcodes and EthFrame.
    type Eip8141Ctx<DB> = revm::context::Context<
        revm::context::BlockEnv,
        TxEnv,
        revm::context::CfgEnv,
        DB,
        Journal<DB>,
        FrameTxContext,
    >;
    let instructions =
        EthInstructions::<EthInterpreter, Eip8141Ctx<DB>>::new_mainnet_with_spec(spec)
            .with_eip8141_opcodes();
    let precompiles =
        PrecompilesMap::from_static(Precompiles::new(PrecompileSpecId::from_spec_id(spec)));

    let mut evm: RevmEvm<
        Eip8141Ctx<DB>,
        (),
        EthInstructions<EthInterpreter, Eip8141Ctx<DB>>,
        PrecompilesMap,
        revm::handler::EthFrame<EthInterpreter>,
    > = RevmEvm::new(ctx, instructions, precompiles);

    if frame_ctx.frames.is_empty() {
        return Ok(ExecutionResult::Revert {
            gas_used: 0,
            output: Bytes::from_static(b"EIP-8141: no frames"),
        });
    }

    // ── Nonce & balance validation ──────────────────────────────────────
    // Read-only validation first.
    {
        let sender_account = evm
            .ctx
            .journaled_state
            .load_account(frame_tx.sender)
            .map_err(EVMError::Database)?;

        if sender_account.info.nonce != frame_tx.nonce {
            return Ok(ExecutionResult::Revert {
                gas_used: 0,
                output: Bytes::from_static(b"EIP-8141: nonce mismatch"),
            });
        }

        let max_cost =
            U256::from(frame_tx.max_fee_per_gas) * U256::from(frame_tx.total_gas_limit());
        if sender_account.info.balance < max_cost {
            return Ok(ExecutionResult::Revert {
                gas_used: 0,
                output: Bytes::from_static(b"EIP-8141: insufficient balance"),
            });
        }
    }

    // Increment nonce and deduct max gas cost upfront (P0#1).
    let max_cost =
        U256::from(frame_tx.max_fee_per_gas) * U256::from(frame_tx.total_gas_limit());
    {
        let mut sender_acc = evm
            .ctx
            .journaled_state
            .load_account_mut(frame_tx.sender)
            .map_err(EVMError::Database)?;
        sender_acc.set_nonce(frame_tx.nonce + 1);
        sender_acc.decr_balance(max_cost);
    }

    // ── Frame execution ──────────────────────────────────────────────────
    // Take an accounting checkpoint so we can revert all frame state on failure
    // while preserving nonce + balance changes made above.
    let accounting_checkpoint = evm.ctx.journaled_state.checkpoint();

    let mut failure: Option<Bytes> = None;
    let mut all_logs: Vec<Log> = Vec::new();
    let mut total_gas_used: u64 = FRAME_TX_INTRINSIC_COST;
    let mut sender_approved = false;

    'frames: for (i, frame_info) in frame_ctx.frames.iter().enumerate() {
        let mode = FrameMode::from_u8(frame_info.mode);

        // Update current frame index in the context.
        evm.ctx.chain.current_frame_index = i;

        // Pre-frame checks: SENDER and DEFAULT frames require prior approval.
        match mode {
            Some(FrameMode::Default) | Some(FrameMode::Sender) => {
                if !sender_approved {
                    failure = Some(Bytes::from_static(b"EIP-8141: sender not approved"));
                    break 'frames;
                }
            }
            Some(FrameMode::Verify) => {}
            None => {
                failure = Some(Bytes::from_static(b"EIP-8141: invalid frame mode"));
                break 'frames;
            }
        }

        // Determine caller based on frame mode.
        let caller = match mode.unwrap() {
            FrameMode::Verify | FrameMode::Default => ENTRY_POINT,
            FrameMode::Sender => frame_tx.sender,
        };

        let is_verify = mode == Some(FrameMode::Verify);

        // For VERIFY: take a checkpoint so we can revert state changes.
        let verify_cp = if is_verify {
            Some(evm.ctx.journaled_state.checkpoint())
        } else {
            None
        };

        // Set TxEnv for this frame.
        evm.ctx.tx = TxEnv::builder()
            .caller(caller)
            .data(frame_info.data.clone())
            .call(frame_info.target)
            .gas_limit(frame_info.gas_limit)
            .build_fill();

        // Execute — returns FrameResult, journal untouched.
        // Do NOT use ? — must clean up on Err before propagating.
        let init_gas = InitialAndFloorGas::new(0, 0);
        let frame_result = match MainnetHandler::default().execution(&mut evm, &init_gas) {
            Ok(r) => r,
            Err(e) => {
                evm.ctx.local.clear();
                evm.frame_stack.clear();
                evm.ctx.journaled_state.discard_tx();
                return Err(e);
            }
        };

        // Check context error (accumulated during execution).
        let ctx_error = core::mem::replace(&mut evm.ctx.error, Ok(()));
        if let Err(e) = ctx_error {
            evm.ctx.local.clear();
            evm.frame_stack.clear();
            evm.ctx.journaled_state.discard_tx();
            return Err(EVMError::from(e));
        }

        // Extract gas info from FrameResult.
        // used() = spent() - min(refunded, spent/5) to honor EVM-level gas refunds.
        let gas_used = frame_result.gas().used();
        let success = frame_result.instruction_result().is_ok();

        // Always add gas_used BEFORE any break (ensures failure path charges correctly).
        total_gas_used = total_gas_used.saturating_add(gas_used);

        // Update frame status in chain context.
        evm.ctx.chain.frames[i].status = Some(success);

        // Clean up execution state for next frame (but NOT commit_tx!).
        evm.ctx.local.clear();
        evm.frame_stack.clear();

        if is_verify {
            // Save ALL mutable chain ctx fields BEFORE revert.
            let saved_sender_approved = evm.ctx.chain.sender_approved;
            let saved_payer_approved = evm.ctx.chain.payer_approved;
            let saved_payer = evm.ctx.chain.payer;
            let saved_frame_status = evm.ctx.chain.frames[i].status;

            // Revert VERIFY state changes — logs truncated too (JournalCheckpoint.log_i).
            evm.ctx.journaled_state.checkpoint_revert(verify_cp.unwrap());

            // Restore chain ctx fields (not part of journal).
            evm.ctx.chain.sender_approved = saved_sender_approved;
            evm.ctx.chain.payer_approved = saved_payer_approved;
            evm.ctx.chain.payer = saved_payer;
            evm.ctx.chain.frames[i].status = saved_frame_status;

            // Do NOT collect logs (reverted by checkpoint_revert — log_i truncation).
            if !success {
                failure = Some(Bytes::from_static(b"EIP-8141: VERIFY frame reverted"));
                break 'frames;
            }
            sender_approved = evm.ctx.chain.sender_approved;
            if !sender_approved {
                failure = Some(Bytes::from_static(
                    b"EIP-8141: VERIFY frame did not call APPROVE",
                ));
                break 'frames;
            }
        } else {
            // DEFAULT/SENDER — state stays in journal.
            if !success {
                failure = Some(Bytes::from_static(b"EIP-8141: frame execution failed"));
                break 'frames;
            }
            // Collect logs (take_logs drains journal logs accumulated during this frame).
            all_logs.extend(evm.ctx.journaled_state.take_logs());
        }
    }

    // ── Single exit block ────────────────────────────────────────────────
    if failure.is_some() {
        // Revert all frame state changes (preserves nonce + balance before checkpoint).
        evm.ctx.journaled_state.checkpoint_revert(accounting_checkpoint);
        all_logs.clear();
    } else {
        evm.ctx.journaled_state.checkpoint_commit();
    }

    // Gas refund — SAME formula for success and failure.
    let effective_gas_price = {
        let base_fee = evm.ctx.block.basefee as u128;
        let tip = (frame_tx.max_fee_per_gas.saturating_sub(base_fee))
            .min(frame_tx.max_priority_fee_per_gas);
        base_fee + tip
    };
    let actual_cost = U256::from(effective_gas_price) * U256::from(total_gas_used);
    let refund = max_cost.saturating_sub(actual_cost);
    if refund > U256::ZERO {
        let mut sender_acc = evm
            .ctx
            .journaled_state
            .load_account_mut(frame_tx.sender)
            .map_err(EVMError::Database)?;
        sender_acc.incr_balance(refund);
    }

    // Single atomic commit to DB.
    let state = evm.finalize();
    evm.commit(state);

    match failure {
        Some(output) => Ok(ExecutionResult::Revert {
            gas_used: total_gas_used,
            output,
        }),
        None => Ok(ExecutionResult::Success {
            reason: SuccessReason::Return,
            gas_used: total_gas_used,
            gas_refunded: 0,
            logs: all_logs,
            output: Output::Call(Bytes::new()),
        }),
    }
}
