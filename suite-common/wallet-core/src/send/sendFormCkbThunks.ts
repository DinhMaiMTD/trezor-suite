import { bech32m } from 'bech32';

import { createThunk } from '@suite-common/redux-utils';
import {
    AddressDisplayOptions,
    ExternalOutput,
    PrecomposedLevels,
    PrecomposedTransaction,
} from '@suite-common/wallet-types';
import {
    calculateMax,
    calculateTotal,
    formatNetworkAmount,
    getExternalComposeOutput,
    isTestnet,
} from '@suite-common/wallet-utils';
import TrezorConnect, { FeeLevel } from '@trezor/connect';
import { BigNumber } from '@trezor/utils/src/bigNumber';

import { SEND_MODULE_PREFIX } from './sendFormConstants';
import {
    ComposeFeeLevelsError,
    ComposeTransactionThunkArguments,
    SignTransactionError,
    SignTransactionThunkArguments,
} from './sendFormTypes';

// CKB minimum cell capacity: 61 CKB = 6100000000 shannons
// (8 bytes capacity + 32 bytes code_hash + 1 byte hash_type + 20 bytes args = 61 bytes)
const MIN_CELL_CAPACITY = '6100000000';

// Estimated transaction size in bytes for fee calculation
// ECDSA: A typical CKB transfer (1-2 inputs, 2 outputs, 65-byte signature) is around 700 bytes
const ESTIMATED_TX_SIZE_ECDSA = 700;
// SPHINCS+: Post-quantum signatures are much larger (~17K+ bytes for SHA2-128f).
// Transaction body ~500 bytes + WitnessArgs overhead 20 bytes + lock field ~17K bytes.
// Using 20000 as a safe upper estimate to avoid PoolRejectedTransactionByMinFeeRate.
const ESTIMATED_TX_SIZE_SPHINCSPLUS = 20000;

// secp256k1_blake160 system cell deps (ECDSA)
const MAINNET_SECP256K1_CELL_DEP = {
    outPoint: {
        txHash: '0x71a7ba8fc96349fea0ed3a5c47992e3b4084b031a42264a018e0072e8172e46c',
        index: 0,
    },
    depType: 'dep_group' as const,
};

const TESTNET_SECP256K1_CELL_DEP = {
    outPoint: {
        txHash: '0xf8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37',
        index: 0,
    },
    depType: 'dep_group' as const,
};

// SPHINCS+ (quantum-resistant) lock script cell deps
// Source: https://github.com/nervosnetwork/quantum-resistant-lock-script
const MAINNET_SPHINCSPLUS_CELL_DEP = {
    outPoint: {
        txHash: '0x4598d00df2f3dc8bc40eee38689a539c94f6cc3720b7a2a6746736daa60f500a',
        index: 0,
    },
    depType: 'code' as const,
};

const TESTNET_SPHINCSPLUS_CELL_DEP = {
    outPoint: {
        txHash: '0x631d9a6049fb1fc3790e89d9daf35abe535b5e754cd8c3404319319710f0b106',
        index: 0,
    },
    depType: 'code' as const,
};

// secp256k1_blake160 lock script code_hash (for reference)
// const SECP256K1_CODE_HASH = '0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8';

/**
 * Decode a CKB Full Address (CKB2021, bech32m) to extract the lock script components.
 * Format: bech32m(hrp, [0x00 | code_hash(32) | hash_type(1) | args(variable)])
 */
const decodeCkbAddress = (
    address: string,
): { codeHash: string; hashType: string; args: string } => {
    const { words } = bech32m.decode(address, 1024);
    const data = bech32m.fromWords(words);
    // data[0] = 0x00 (full format type)
    const codeHash =
        '0x' +
        Array.from(data.slice(1, 33))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    const hashTypeByte = data[33];
    let hashType: string;
    switch (hashTypeByte) {
        case 0x00:
            hashType = 'data';
            break;
        case 0x01:
            hashType = 'type';
            break;
        case 0x02:
            hashType = 'data1';
            break;
        default:
            hashType = 'data2';
    }
    const args =
        '0x' +
        Array.from(data.slice(34))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');

    return { codeHash, hashType, args };
};

/**
 * Calculate CKB transaction fee from fee rate.
 * feeRatePerKB is in shannons/KB from the CKB node.
 */
const calculateCkbFee = (feeRatePerKB: string, txSizeBytes: number): string => {
    const rate = new BigNumber(feeRatePerKB);
    const fee = rate.times(txSizeBytes).dividedBy(1000).integerValue(BigNumber.ROUND_CEIL);

    // Minimum fee of 1000 shannons (0.00001 CKB)
    return BigNumber.max(fee, 1000).toString();
};

/**
 * Convert ECDSA signature from Trezor format to CKB format.
 *
 * Trezor's secp256k1.sign(compressed=True) returns 65 bytes: [v(1) || r(32) || s(32)]
 * where v = 27 + recovery_id + 4 = 31 + recovery_id (compressed keys add 4).
 *
 * CKB's secp256k1_blake160 lock script expects 65 bytes: [r(32) || s(32) || recovery_id(1)]
 * where recovery_id is 0 or 1, parsed via secp256k1_ecdsa_recoverable_signature_parse_compact.
 *
 * NOTE: This function is only for ECDSA signatures. SPHINCS+ signatures are used as-is.
 */
const convertTrezorSigToCkb = (sigHex: string): string => {
    const sig = sigHex.startsWith('0x') ? sigHex.slice(2) : sigHex;
    // sig is 130 hex chars = 65 bytes: v(2 hex) + r(64 hex) + s(64 hex)
    const v = parseInt(sig.slice(0, 2), 16);
    // v = 31 + recid for compressed, v = 27 + recid for uncompressed
    const recid = v >= 31 ? v - 31 : v - 27;
    const rs = sig.slice(2); // r(32 bytes) || s(32 bytes) = 128 hex chars

    return rs + recid.toString(16).padStart(2, '0');
};

/**
 * Build a serialized WitnessArgs in Molecule format with the given lock (signature).
 * WitnessArgs { lock: BytesOpt, input_type: BytesOpt, output_type: BytesOpt }
 *
 * For secp256k1_blake160 (ECDSA): the lock is a 65-byte recoverable signature [r||s||recid].
 * For SPHINCS+: the lock is a variable-length post-quantum signature (~7856 bytes).
 * The signature data is placed in the lock field as raw bytes.
 */
const buildWitnessArgs = (signatureHex: string): string => {
    // Remove 0x prefix if present
    const sig = signatureHex.startsWith('0x') ? signatureHex.slice(2) : signatureHex;
    const sigBytes = sig.length / 2; // 65 for ECDSA, ~7856 for SPHINCS+

    // Molecule Table layout for WitnessArgs (3 fields):
    // header: full_size(4) + offset_0(4) + offset_1(4) + offset_2(4) = 16 bytes
    // lock: Bytes = length(4) + data(sigBytes)
    // input_type: None (0 bytes)
    // output_type: None (0 bytes)
    const headerSize = 16;
    const lockSize = 4 + sigBytes; // Bytes type: 4-byte length + data
    const fullSize = headerSize + lockSize;

    const offset0 = headerSize;
    const offset1 = headerSize + lockSize;
    const offset2 = offset1; // Both empty

    const toLE32 = (n: number): string => {
        const buf = new ArrayBuffer(4);
        new DataView(buf).setUint32(0, n, true);

        return Array.from(new Uint8Array(buf))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    };

    return (
        '0x' + toLE32(fullSize) + toLE32(offset0) + toLE32(offset1) + toLE32(offset2) + toLE32(sigBytes) + sig
    );
};

/**
 * Calculate compose result for a CKB transaction at a given fee level.
 */
const calculate = (
    availableBalance: string,
    output: ExternalOutput,
    feeLevel: FeeLevel,
    isSphincsPlus = false,
): PrecomposedTransaction => {
    // Calculate fee based on estimated transaction size
    const estimatedTxSize = isSphincsPlus ? ESTIMATED_TX_SIZE_SPHINCSPLUS : ESTIMATED_TX_SIZE_ECDSA;
    const feeInShannons = calculateCkbFee(feeLevel.feePerUnit, estimatedTxSize);

    let amount: string;
    let max: string | undefined;

    if (output.type === 'send-max' || output.type === 'send-max-noaddress') {
        const maxAmount = calculateMax(availableBalance, feeInShannons);
        max = maxAmount;
        amount = maxAmount;
    } else {
        amount = output.amount;
    }

    // Check if amount is enough
    if (new BigNumber(amount).isLessThanOrEqualTo(0)) {
        return {
            type: 'error',
            error: 'AMOUNT_IS_NOT_ENOUGH',
            errorMessage: { id: 'AMOUNT_IS_NOT_ENOUGH' },
        } as const;
    }

    // Check minimum amount (CKB requires minimum 61 CKB per output cell)
    if (new BigNumber(amount).isLessThan(MIN_CELL_CAPACITY)) {
        return {
            type: 'error',
            error: 'AMOUNT_IS_TOO_LOW',
            errorMessage: { id: 'AMOUNT_IS_TOO_LOW' },
        } as const;
    }

    const totalSpent = new BigNumber(calculateTotal(amount, feeInShannons));

    if (totalSpent.isGreaterThan(availableBalance)) {
        return {
            type: 'error',
            error: 'AMOUNT_IS_NOT_ENOUGH',
            errorMessage: { id: 'AMOUNT_IS_NOT_ENOUGH' },
        } as const;
    }

    // Check if change is below minimum cell capacity
    const change = new BigNumber(availableBalance).minus(totalSpent);
    let adjustedFee = feeInShannons;

    if (change.isGreaterThan(0) && change.isLessThan(MIN_CELL_CAPACITY)) {
        // Change too small for a cell, add it to fee
        adjustedFee = new BigNumber(feeInShannons).plus(change).toString();
    }

    const payloadData = {
        type: 'nonfinal' as const,
        totalSpent: totalSpent.toString(),
        max,
        fee: adjustedFee,
        feePerByte: feeLevel.feePerUnit,
        bytes: estimatedTxSize,
        inputs: [],
    };

    if (output.type === 'send-max' || output.type === 'payment') {
        return {
            ...payloadData,
            type: 'final',
            inputs: [],
            outputsPermutation: [0],
            outputs: [
                {
                    address: output.address,
                    amount,
                    script_type: 'PAYTOADDRESS',
                },
            ],
        };
    }

    return payloadData;
};

export const composeCkbTransactionFeeLevelsThunk = createThunk<
    PrecomposedLevels,
    ComposeTransactionThunkArguments,
    { rejectValue: ComposeFeeLevelsError }
>(
    `${SEND_MODULE_PREFIX}/composeCkbTransactionFeeLevelsThunk`,
    ({ formState, composeContext }, { rejectWithValue }) => {
        const { account, network, feeInfo } = composeContext;
        const composeOutputs = getExternalComposeOutput(formState, account, network);
        if (!composeOutputs) {
            return rejectWithValue({
                error: 'fee-levels-compose-failed',
                message: 'Unable to compose output.',
            });
        }

        const { output } = composeOutputs;
        const { availableBalance } = account;
        const isSphincsPlus = account.accountType === 'sphincsplus';

        const predefinedLevels = feeInfo.levels.filter(l => l.label !== 'custom');
        // In case when selectedFee is set to 'custom', construct this FeeLevel from values
        if (formState.selectedFee === 'custom') {
            predefinedLevels.push({
                label: 'custom',
                feePerUnit: formState.feePerUnit,
                blocks: -1,
            });
        }

        // Wrap response into PrecomposedLevels object where key is a FeeLevel label
        const resultLevels: PrecomposedLevels = {};
        const response = predefinedLevels.map(level =>
            calculate(availableBalance, output, level, isSphincsPlus),
        );
        response.forEach((tx, index) => {
            const feeLabel = predefinedLevels[index].label as FeeLevel['label'];
            resultLevels[feeLabel] = tx;
        });

        const hasAtLeastOneValid = response.find(r => r.type !== 'error');
        // There is no valid tx in predefinedLevels and there is no custom level
        if (!hasAtLeastOneValid && !resultLevels.custom) {
            const { minFee } = feeInfo;
            const lastKnownFee = predefinedLevels[predefinedLevels.length - 1].feePerUnit;
            let maxFee = new BigNumber(lastKnownFee).minus(1);
            const customLevels: FeeLevel[] = [];
            while (maxFee.gte(minFee)) {
                customLevels.push({ feePerUnit: maxFee.toString(), label: 'custom', blocks: -1 });
                maxFee = maxFee.minus(1);
            }

            const customLevelsResponse = customLevels.map(level =>
                calculate(availableBalance, output, level, isSphincsPlus),
            );

            const customValid = customLevelsResponse.findIndex(r => r.type !== 'error');
            if (customValid >= 0) {
                resultLevels.custom = customLevelsResponse[customValid];
            }
        }

        // Format max (calculate sends it as shannons)
        Object.keys(resultLevels).forEach(key => {
            const tx = resultLevels[key];
            if (tx.type !== 'error' && tx.max) {
                tx.max = formatNetworkAmount(tx.max, account.symbol);
            }
        });

        return resultLevels;
    },
);

export const signCkbSendFormTransactionThunk = createThunk<
    { serializedTx: string },
    SignTransactionThunkArguments,
    { rejectValue: SignTransactionError }
>(
    `${SEND_MODULE_PREFIX}/signCkbSendFormTransactionThunk`,
    async (
        { formState, precomposedTransaction, selectedAccount, device },
        { getState, extra, rejectWithValue },
    ) => {
        const {
            selectors: { selectAddressDisplayType },
        } = extra;

        const addressDisplayType = selectAddressDisplayType(getState());
        const testnet = isTestnet(selectedAccount.symbol);

        // 1. Get recipient address and amount
        const recipientAddress = formState.outputs[0].address;
        const amountRaw = precomposedTransaction.outputs[0].amount;
        const amount = String(amountRaw);
        const {fee} = precomposedTransaction;

        if (!recipientAddress || !amount) {
            return rejectWithValue({
                error: 'sign-transaction-failed',
                message: 'Missing recipient address or amount.',
            });
        }

        // 2. Get UTXOs (live cells) from the account
        const utxos = selectedAccount.utxo;
        if (!utxos || utxos.length === 0) {
            return rejectWithValue({
                error: 'sign-transaction-failed',
                message: 'No UTXOs available for this account.',
            });
        }

        // 3. Select UTXOs to cover amount + fee
        const totalNeeded = new BigNumber(amount).plus(fee);
        const sortedUtxos = [...utxos].sort((a, b) =>
            new BigNumber(b.amount).comparedTo(new BigNumber(a.amount)) ?? 0,
        );

        const selectedUtxos: typeof utxos = [];
        let totalInput = new BigNumber(0);

        for (const utxo of sortedUtxos) {
            selectedUtxos.push(utxo);
            totalInput = totalInput.plus(utxo.amount);
            if (totalInput.gte(totalNeeded)) break;
        }

        if (totalInput.isLessThan(totalNeeded)) {
            return rejectWithValue({
                error: 'sign-transaction-failed',
                message: 'Insufficient UTXOs to cover amount and fee.',
            });
        }

        // 4. Calculate change
        let changeAmount = totalInput.minus(totalNeeded);
        let _actualFee = new BigNumber(fee);
        const hasChange =
            changeAmount.isGreaterThan(0) &&
            changeAmount.gte(MIN_CELL_CAPACITY);

        if (changeAmount.isGreaterThan(0) && changeAmount.isLessThan(MIN_CELL_CAPACITY)) {
            // Change too small for a cell, add to fee
            _actualFee = _actualFee.plus(changeAmount);
            changeAmount = new BigNumber(0);
        }

        // 5. Decode recipient lock script
        const recipientLock = decodeCkbAddress(recipientAddress);

        // 6. Decode sender lock script (from account descriptor)
        const senderLock = decodeCkbAddress(selectedAccount.descriptor);

        // 7. Build CKB transaction for Trezor signing
        const isSphincsPlus = selectedAccount.accountType === 'sphincsplus';

        // Validate lock script hash_type for SPHINCS+ addresses
        if (isSphincsPlus) {
            const expectedHashType = testnet ? 'data1' : 'type';
            if (senderLock.hashType !== expectedHashType) {
                const network = testnet ? 'testnet' : 'mainnet';
                console.error(
                    `[CKB SPHINCS+] HASH_TYPE MISMATCH! Firmware uses '${senderLock.hashType}' but ${network} deployment requires '${expectedHashType}'.`
                );
            }
        }

        let cellDep;
        if (isSphincsPlus) {
            cellDep = testnet ? TESTNET_SPHINCSPLUS_CELL_DEP : MAINNET_SPHINCSPLUS_CELL_DEP;
        } else {
            cellDep = testnet ? TESTNET_SECP256K1_CELL_DEP : MAINNET_SECP256K1_CELL_DEP;
        }

        const inputs = selectedUtxos.map(utxo => ({
            since: '0',
            previousOutput: {
                txHash: utxo.txid.startsWith('0x') ? utxo.txid : `0x${utxo.txid}`,
                index: utxo.vout,
            },
            capacity: utxo.amount,
        }));

        const outputs: Array<{
            capacity: string;
            lock: {
                codeHash: string;
                hashType: 'type' | 'data' | 'data1' | 'data2';
                args: string;
            };
        }> = [
            {
                capacity: amount,
                lock: {
                    codeHash: recipientLock.codeHash,
                    hashType: recipientLock.hashType as 'type' | 'data' | 'data1' | 'data2',
                    args: recipientLock.args,
                },
            },
        ];

        // Add change output if needed
        if (hasChange) {
            outputs.push({
                capacity: changeAmount.toString(),
                lock: {
                    codeHash: senderLock.codeHash,
                    hashType: senderLock.hashType as 'type' | 'data' | 'data1' | 'data2',
                    args: senderLock.args,
                },
            });
        }

        let outputsData = outputs.map(() => '0x');

        // 7.5. Pre-signing fee adjustment: ensure fee covers the actual transaction size.
        // This MUST happen BEFORE signing, because modifying outputs after signing
        // would change the tx_hash and invalidate the signature (causing CKB error 107).
        //
        // The compose phase estimates fee using a generic TX size, but on testnets
        // with very low fee rates the minimum fee (1000 shannons) may be insufficient
        // for the actual serialized transaction (especially SPHINCS+ with ~17KB witnesses).
        {
            // Pre-compute expected witness size based on signing mode
            // ECDSA WitnessArgs: header(16) + lockLen(4) + signature(65) = 85 bytes
            // SPHINCS+ WitnessArgs: header(16) + lockLen(4) + multisig_prefix(5) + pubkey(32) + sig(17088) = 17145 bytes
            const witnessArgsSize = isSphincsPlus ? 17145 : 85;
            const numInputs = selectedUtxos.length;
            const numOutputs = outputs.length;

            // Molecule serialization size calculation
            const cellDepsVec = 4 + 1 * 37; // FixVec: count(4) + 1 × CellDep(37)
            const headerDepsVec = 4; // FixVec: count(4), empty
            const inputsVec = 4 + numInputs * 44; // FixVec: count(4) + items
            const outputsVec = 4 + 4 * numOutputs + numOutputs * 85; // DynVec
            const outputsDataVec = 4 + 4 * numOutputs + numOutputs * 4; // DynVec
            const rawTxHeader = 4 + 6 * 4; // total_size(4) + 6 offsets
            const rawTxSize =
                rawTxHeader + 4 + cellDepsVec + headerDepsVec + inputsVec + outputsVec + outputsDataVec;
            // Witnesses: DynVec with first witness = witnessArgs, rest empty
            const witnessesVec = 4 + 4 * numInputs + witnessArgsSize;
            // Full Transaction table: total_size(4) + 2 offsets(8) + raw + witnesses
            const actualTxSize = 4 + 2 * 4 + rawTxSize + witnessesVec;
            // 2% safety margin for Molecule overhead variations
            const txSizeWithMargin = Math.ceil(actualTxSize * 1.02);
            const PRE_SIGN_MIN_FEE_RATE = 1000; // shannons per KB (CKB minimum)
            const requiredFee = Math.max(
                Math.ceil((txSizeWithMargin * PRE_SIGN_MIN_FEE_RATE) / 1000),
                1000,
            );

            const currentPreSignFee = totalInput
                .minus(new BigNumber(amount))
                .minus(hasChange ? changeAmount : new BigNumber(0));

            if (currentPreSignFee.isLessThan(requiredFee)) {
                // Fee is insufficient — recalculate change with required fee
                const newTotalNeeded = new BigNumber(amount).plus(requiredFee);
                let newChange = totalInput.minus(newTotalNeeded);

                if (newChange.isGreaterThan(0) && newChange.isLessThan(MIN_CELL_CAPACITY)) {
                    // Change dust — absorb into fee
                    _actualFee = totalInput.minus(new BigNumber(amount));
                    newChange = new BigNumber(0);
                } else if (newChange.isLessThanOrEqualTo(0)) {
                    return rejectWithValue({
                        error: 'sign-transaction-failed',
                        message: `Insufficient balance: need ${requiredFee} shannons fee but only ${currentPreSignFee.toString()} available.`,
                    });
                } else {
                    _actualFee = new BigNumber(requiredFee);
                }

                changeAmount = newChange;

                // Rebuild outputs with adjusted change
                outputs.length = 1; // Keep only the recipient output
                if (changeAmount.isGreaterThan(0)) {
                    outputs.push({
                        capacity: changeAmount.toString(),
                        lock: {
                            codeHash: senderLock.codeHash,
                            hashType: senderLock.hashType as 'type' | 'data' | 'data1' | 'data2',
                            args: senderLock.args,
                        },
                    });
                }
                outputsData = outputs.map(() => '0x');
            }
        }

        const transaction = {
            version: 0,
            cellDeps: [cellDep],
            headerDeps: [] as string[],
            inputs,
            outputs,
            outputsData,
        };

        // 8. Sign with Trezor
        const response = await TrezorConnect.ckbSignTransaction({
            device: {
                path: device.path,
                instance: device.instance,
                state: device.state,
                useEmptyPassphrase: device.useEmptyPassphrase,
            },
            path: selectedAccount.path,
            transaction,
            network: testnet ? 'Testnet' : 'Mainnet',
            fee: Number(_actualFee.toString()),
            chunkify: addressDisplayType === AddressDisplayOptions.CHUNKED,
            sphincsplus: selectedAccount.accountType === 'sphincsplus' || undefined,
        });

        if (!response.success) {
            return rejectWithValue({
                error: 'sign-transaction-failed',
                message: response.payload.error,
            });
        }

        // 9. Build witnesses
        const { signature } = response.payload;
        const witnesses: string[] = [];

        // For ECDSA: convert signature from Trezor format [v||r||s] to CKB format [r||s||recid]
        // For SPHINCS+: use the raw signature directly (no conversion needed)
        let ckbSignature: string;
        if (isSphincsPlus) {
            ckbSignature = signature.startsWith('0x') ? signature.slice(2) : signature;
        } else {
            ckbSignature = convertTrezorSigToCkb(signature);
        }

        // First input gets the WitnessArgs with signature
        witnesses.push(buildWitnessArgs(ckbSignature));

        // Additional inputs from the same lock group get empty witnesses
        for (let i = 1; i < selectedUtxos.length; i++) {
            witnesses.push('0x');
        }

        // 10. Post-signing verification: ensure the fee is still valid.
        // NOTE: We do NOT modify outputs here — the transaction was already signed.
        // Any output modification would change the tx_hash and invalidate the signature.
        // The pre-signing fee adjustment (step 7.5) ensures the fee is always sufficient.
        {
            const witnessBytes = witnesses.reduce((sum, w) => {
                const hex = w.startsWith('0x') ? w.slice(2) : w;

                return sum + hex.length / 2;
            }, 0);
            const numInputs = selectedUtxos.length;
            const numOutputs = outputs.length;
            const cellDepsVec = 4 + 4 + 1 * 37;
            const headerDepsVec = 4 + 4;
            const inputsVec = 4 + 4 + numInputs * 44;
            const outputsVec = 4 + 4 * numOutputs + numOutputs * 85;
            const outputsDataVec = 4 + 4 * numOutputs + numOutputs * 4;
            const rawTxSize =
                4 + 4 + 4 + cellDepsVec + headerDepsVec + inputsVec + outputsVec + outputsDataVec;
            const witnessesVec = 4 + 4 * numInputs + witnessBytes;
            const actualTxSize = 4 + rawTxSize + witnessesVec;
            const txSizeWithMargin = Math.ceil(actualTxSize * 1.02);
            const POST_SIGN_MIN_FEE_RATE = 1000;
            const requiredFee = Math.ceil(
                (txSizeWithMargin * POST_SIGN_MIN_FEE_RATE) / 1000,
            );
            const postSignFee = totalInput
                .minus(new BigNumber(amount))
                .minus(changeAmount.isGreaterThan(0) ? changeAmount : new BigNumber(0));

            if (postSignFee.isLessThan(requiredFee)) {
                // Fee is still insufficient after pre-signing adjustment — reject
                return rejectWithValue({
                    error: 'sign-transaction-failed',
                    message: `Insufficient fee: need ${requiredFee} shannons but only ${postSignFee.toString()} available. Transaction cannot be sent.`,
                });
            }
        }

        // 11. Build the full signed transaction for broadcasting
        // Use the format expected by the ccc library's sendTransactionNoCache (TransactionLike)
        // NumLike fields accept string | number | bigint; using strings for JSON serialization safety
        const fullTransaction = {
            version: 0,
            cellDeps: [
                {
                    outPoint: {
                        txHash: cellDep.outPoint.txHash,
                        index: cellDep.outPoint.index,
                    },
                    depType: cellDep.depType === 'dep_group' ? 'depGroup' : 'code',
                },
            ],
            headerDeps: [] as string[],
            inputs: inputs.map(input => ({
                since: 0,
                previousOutput: {
                    txHash: input.previousOutput.txHash,
                    index: input.previousOutput.index,
                },
            })),
            outputs: outputs.map(output => ({
                capacity: output.capacity,
                lock: {
                    codeHash: output.lock.codeHash,
                    hashType: output.lock.hashType,
                    args: output.lock.args,
                },
            })),
            outputsData,
            witnesses,
        };

        const serializedTx = JSON.stringify(fullTransaction);

        return { serializedTx };
    },
);
