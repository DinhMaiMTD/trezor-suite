import {
    Address,
    type Client as CccClient,
    ClientPublicMainnet,
    ClientPublicTestnet,
} from '@ckb-ccc/core';

import type { AccountInfo, Response, Transaction, Utxo } from '@trezor/blockchain-link-types';
import { MESSAGES, RESPONSES } from '@trezor/blockchain-link-types/src/constants';
import { CustomError } from '@trezor/blockchain-link-types/src/constants/errors';
import type * as MessageTypes from '@trezor/blockchain-link-types/src/messages';

import { BaseWorker, CONTEXT, ContextType } from '../baseWorker';

type Context = ContextType<CccClient>;
type Request<T> = T & Context;

// CKB has 8 decimal places (1 CKB = 10^8 shannons)
const CKB_DECIMALS = 8;

const getInfo = async (request: Request<MessageTypes.GetInfo>) => {
    const client = await request.connect();
    const tip = await client.getTip();

    return {
        type: RESPONSES.GET_INFO,
        payload: {
            url: client.url,
            name: 'CKB',
            shortcut: 'CKB',
            decimals: CKB_DECIMALS,
            testnet: client.addressPrefix === 'ckt',
            version: '0.1.0',
            network: client.addressPrefix === 'ckt' ? 'testnet' : 'mainnet',
            blockHeight: Number(tip),
            blockHash: '0x',
        },
    } as const;
};

const getAccountInfo = async (request: Request<MessageTypes.GetAccountInfo>) => {
    const { payload } = request;
    const client = await request.connect();

    // Default empty account state
    const account: AccountInfo = {
        descriptor: payload.descriptor,
        balance: '0',
        availableBalance: '0',
        empty: true,
        history: {
            total: -1,
            unconfirmed: 0,
            transactions: undefined,
        },
    };

    try {
        // Parse CKB address to get lock script
        const address = await Address.fromString(payload.descriptor, client);
        const lockScript = address.script;

        // Get balance (in shannons)
        const balance = await client.getBalanceSingle(lockScript);
        const balanceStr = balance.toString();

        account.balance = balanceStr;
        account.availableBalance = balanceStr;
        account.empty = balance === BigInt(0);

        // Get transaction history if requested.
        // History fetching is best-effort and should not break discovery.
        if (payload.details === 'txs') {
            try {
                const transactions: AccountInfo['history']['transactions'] = [];
                let total = 0;

                // Cache fetched transactions to avoid redundant RPC calls
                const txCache = new Map<
                    string,
                    Awaited<ReturnType<typeof client.getTransaction>>
                >();
                const fetchTx = async (hash: string) => {
                    const cached = txCache.get(hash);
                    if (cached !== undefined) return cached;
                    const result = await client.getTransaction(hash);
                    txCache.set(hash, result);

                    return result;
                };

                // Cache block timestamps to avoid redundant header fetches
                const blockTimestampCache = new Map<number, number>();
                const getBlockTimestamp = async (
                    blockNum: number,
                ): Promise<number | undefined> => {
                    const cached = blockTimestampCache.get(blockNum);
                    if (cached !== undefined) return cached;
                    try {
                        const header =
                            await client.getHeaderByNumber(blockNum);
                        if (header) {
                            // CKB timestamp is in milliseconds, convert to seconds
                            const ts = Number(header.timestamp) / 1000;
                            blockTimestampCache.set(blockNum, ts);

                            return ts;
                        }
                    } catch {
                        // ignore header fetch failures
                    }

                    return undefined;
                };

                for await (const tx of client.findTransactionsByLock(
                    lockScript,
                    undefined,
                    true, // groupByTransaction
                    'desc',
                    payload.pageSize || 25,
                )) {
                    total++;
                    const txResponse = await fetchTx(String(tx.txHash));
                    if (txResponse) {
                        const txObj = txResponse.transaction;

                        let myInputSum = BigInt(0);
                        let myOutputSum = BigInt(0);
                        let totalInputSum = BigInt(0);
                        let totalOutputSum = BigInt(0);

                        const vin: Transaction['details']['vin'] = [];
                        const vout: Transaction['details']['vout'] = [];

                        // Resolve input amounts by fetching referenced previous outputs
                        for (let i = 0; i < txObj.inputs.length; i++) {
                            const input = txObj.inputs[i];
                            try {
                                const prevHash = String(
                                    input.previousOutput.txHash,
                                );
                                // Skip cellbase inputs (all-zero hash)
                                if (/^0x0+$/.test(prevHash)) {
                                    vin.push({
                                        n: i,
                                        addresses: [],
                                        isAddress: false,
                                        coinbase:
                                            'cellbase',
                                    });
                                    continue;
                                }

                                const prevTxResponse = await fetchTx(prevHash);
                                if (prevTxResponse) {
                                    const idx = Number(
                                        input.previousOutput.index,
                                    );
                                    const prevOutput =
                                        prevTxResponse.transaction.outputs[idx];
                                    if (prevOutput) {
                                        const cap = BigInt(
                                            prevOutput.capacity,
                                        );
                                        const isOwn =
                                            prevOutput.lock.eq(lockScript);
                                        totalInputSum += cap;
                                        if (isOwn) {
                                            myInputSum += cap;
                                        }
                                        vin.push({
                                            n: i,
                                            addresses: [],
                                            isAddress: true,
                                            isOwn,
                                            value: cap.toString(),
                                        });
                                    }
                                }
                            } catch {
                                // Skip unresolvable inputs
                            }
                        }

                        // Calculate output amounts
                        for (let i = 0; i < txObj.outputs.length; i++) {
                            const output = txObj.outputs[i];
                            const cap = BigInt(output.capacity);
                            const isOwn = output.lock.eq(lockScript);
                            totalOutputSum += cap;
                            if (isOwn) {
                                myOutputSum += cap;
                            }
                            vout.push({
                                n: i,
                                addresses: [],
                                isAddress: true,
                                isOwn,
                                value: cap.toString(),
                            });
                        }

                        const fee =
                            totalInputSum > totalOutputSum
                                ? (totalInputSum - totalOutputSum).toString()
                                : '0';

                        let type: Transaction['type'];
                        let amount: string;

                        if (
                            myInputSum > BigInt(0) &&
                            myInputSum === totalInputSum &&
                            myOutputSum === totalOutputSum
                        ) {
                            // All inputs & outputs belong to the user
                            type = 'self';
                            amount = fee;
                        } else if (myInputSum > myOutputSum) {
                            type = 'sent';
                            amount = (
                                myInputSum - myOutputSum
                            ).toString();
                        } else if (myOutputSum > BigInt(0)) {
                            type = 'recv';
                            amount = (
                                myOutputSum - myInputSum
                            ).toString();
                        } else {
                            type = 'unknown';
                            amount = '0';
                        }

                        // Get block timestamp for graph history support
                        const blockNum = tx.blockNumber
                            ? Number(tx.blockNumber)
                            : undefined;
                        const blockTime = blockNum
                            ? await getBlockTimestamp(blockNum)
                            : undefined;

                        transactions.push({
                            type,
                            txid: String(txObj.hash()).replace(/^0x/, ''),
                            blockHeight: blockNum,
                            blockTime,
                            amount,
                            fee,
                            targets: [],
                            tokens: [],
                            internalTransfers: [],
                            details: {
                                vin,
                                vout,
                                size: 0,
                                totalInput: totalInputSum.toString(),
                                totalOutput: totalOutputSum.toString(),
                            },
                        });
                    }

                    // Limit to page size
                    if (total >= (payload.pageSize || 25)) break;
                }

                account.history = {
                    total,
                    unconfirmed: 0,
                    transactions,
                };
            } catch {
                account.history = {
                    total: 0,
                    unconfirmed: 0,
                    transactions: [],
                };
            }
        }
    } catch (error: unknown) {
        // If account doesn't exist or other error, return empty account
        if (
            error instanceof Error &&
            (error.message.includes('not found') || error.message.includes('Unknown'))
        ) {
            return {
                type: RESPONSES.GET_ACCOUNT_INFO,
                payload: account,
            } as const;
        }
        throw error;
    }

    return {
        type: RESPONSES.GET_ACCOUNT_INFO,
        payload: account,
    } as const;
};

const getTransaction = async ({ connect, payload }: Request<MessageTypes.GetTransaction>) => {
    const client = await connect();
    const txResponse = await client.getTransaction(`0x${payload}`);

    if (!txResponse) {
        throw new CustomError('Transaction', 'Transaction not found');
    }

    const tx: Transaction = {
        type: 'sent',
        txid: payload,
        blockHeight: txResponse.blockNumber ? Number(txResponse.blockNumber) : undefined,
        blockTime: undefined,
        amount: '0',
        fee: '0',
        targets: [],
        tokens: [],
        internalTransfers: [],
        details: {
            vin: [],
            vout: [],
            size: 0,
            totalInput: '0',
            totalOutput: '0',
        },
    };

    return {
        type: RESPONSES.GET_TRANSACTION,
        payload: tx,
    } as const;
};

const pushTransaction = async ({ connect, payload }: Request<MessageTypes.PushTransaction>) => {
    const client = await connect();
    // payload.hex contains the serialized transaction
    const txHash = await client.sendTransactionNoCache(JSON.parse(payload.hex));

    return {
        type: RESPONSES.PUSH_TRANSACTION,
        payload: txHash.slice(2), // remove '0x' prefix
    } as const;
};

const estimateFee = async (request: Request<MessageTypes.EstimateFee>) => {
    const client = await request.connect();
    const feeRate = await client.getFeeRate();

    // feeRate is in shannons/KB
    const feePerUnit = feeRate.toString();

    const payload =
        request.payload && Array.isArray(request.payload.blocks)
            ? request.payload.blocks.map(() => ({ feePerUnit }))
            : [{ feePerUnit }];

    return {
        type: RESPONSES.ESTIMATE_FEE,
        payload,
    } as const;
};

// Block subscription via polling
let blockPollInterval: ReturnType<typeof setInterval> | undefined;

const subscribeBlock = async (ctx: Context) => {
    if (!ctx.state.getSubscription('block')) {
        ctx.state.addSubscription('block');

        const client = await ctx.connect();
        let lastTip = Number(await client.getTip());

        blockPollInterval = setInterval(async () => {
            try {
                const currentTip = Number(await client.getTip());
                if (currentTip > lastTip) {
                    lastTip = currentTip;
                    ctx.post({
                        id: -1,
                        type: RESPONSES.NOTIFICATION,
                        payload: {
                            type: 'block',
                            payload: {
                                blockHeight: currentTip,
                                blockHash: '0x',
                            },
                        },
                    });
                }
            } catch {
                // ignore polling errors
            }
        }, 15000); // Poll every 15 seconds
    }

    return { subscribed: true };
};

const unsubscribeBlock = ({ state }: Context) => {
    if (blockPollInterval) {
        clearInterval(blockPollInterval);
        blockPollInterval = undefined;
    }
    state.removeSubscription('block');
};

const subscribe = async (request: Request<MessageTypes.Subscribe>) => {
    const { payload } = request;

    let response: { subscribed: boolean };
    if (payload.type === 'block') {
        response = await subscribeBlock(request);
    } else if (payload.type === 'accounts' || payload.type === 'addresses') {
        // Basic address subscription - store addresses for notification
        if (payload.type === 'accounts') {
            request.state.addAccounts(payload.accounts);
        } else {
            request.state.addAddresses(payload.addresses);
        }
        response = { subscribed: true };
    } else {
        throw new CustomError('invalid_param', '+type');
    }

    return {
        type: RESPONSES.SUBSCRIBE,
        payload: response,
    } as const;
};

const unsubscribe = (request: Request<MessageTypes.Unsubscribe>) => {
    const { payload } = request;

    if (payload.type === 'block') {
        unsubscribeBlock(request);
    } else if (payload.type === 'accounts') {
        request.state.removeAccounts(payload.accounts ?? []);
    } else if (payload.type === 'addresses') {
        request.state.removeAddresses(payload.addresses ?? []);
    }

    return {
        type: RESPONSES.UNSUBSCRIBE,
        payload: { subscribed: request.state.getAddresses().length > 0 },
    } as const;
};

const getAccountUtxo = async (request: Request<MessageTypes.GetAccountUtxo>) => {
    const descriptor = request.payload;
    const client = await request.connect();

    try {
        const address = await Address.fromString(descriptor, client);
        const lockScript = address.script;

        // Collect CKB live cells as UTXOs
        const utxos: Utxo[] = [];
        for await (const cell of client.findCellsByLock(lockScript, undefined, true)) {
            utxos.push({
                txid: cell.outPoint.txHash.slice(2), // remove '0x' prefix
                vout: Number(cell.outPoint.index),
                amount: cell.cellOutput.capacity.toString(),
                blockHeight: 0, // CKB cells don't carry block height directly
                address: descriptor,
                path: '',
                confirmations: 1,
            });
        }

        return {
            type: RESPONSES.GET_ACCOUNT_UTXO,
            payload: utxos,
        } as const;
    } catch {
        // Return empty UTXO set on any error (e.g. address parse failure, RPC error)
        return {
            type: RESPONSES.GET_ACCOUNT_UTXO,
            payload: [] as Utxo[],
        } as const;
    }
};

const onRequest = (request: Request<MessageTypes.Message>) => {
    switch (request.type) {
        case MESSAGES.GET_INFO:
            return getInfo(request);
        case MESSAGES.GET_ACCOUNT_INFO:
            return getAccountInfo(request);
        case MESSAGES.GET_ACCOUNT_UTXO:
            return getAccountUtxo(request);
        case MESSAGES.GET_TRANSACTION:
            return getTransaction(request);
        case MESSAGES.ESTIMATE_FEE:
            return estimateFee(request);
        case MESSAGES.PUSH_TRANSACTION:
            return pushTransaction(request);
        case MESSAGES.SUBSCRIBE:
            return subscribe(request);
        case MESSAGES.UNSUBSCRIBE:
            return unsubscribe(request);
        default:
            throw new CustomError('worker_unknown_request', `+${request.type}`);
    }
};

class CkbWorker extends BaseWorker<CccClient> {
    protected isConnected(client: CccClient | undefined): client is CccClient {
        return client !== undefined;
    }

    async tryConnect(url: string): Promise<CccClient> {
        // Determine if mainnet or testnet based on url or settings
        const isTestnet =
            url.includes('testnet') || this.settings.name?.toLowerCase().includes('tckb');

        const client = isTestnet
            ? new ClientPublicTestnet({ url })
            : new ClientPublicMainnet({ url });

        // Verify connection by fetching tip
        await client.getTip();

        this.post({ id: -1, type: RESPONSES.CONNECTED });

        return client;
    }

    disconnect() {
        if (blockPollInterval) {
            clearInterval(blockPollInterval);
            blockPollInterval = undefined;
        }
        this.cleanup();

        return Promise.resolve();
    }

    async messageHandler(event: { data: MessageTypes.Message }) {
        try {
            if (await super.messageHandler(event)) return true;

            const request: Request<MessageTypes.Message> = {
                ...event.data,
                connect: () => this.connect(),
                post: (data: Response) => this.post(data),
                state: this.state,
            };

            const response = await onRequest(request);
            this.post({ id: event.data.id, ...response });
        } catch (error: unknown) {
            this.errorResponse(event.data.id, error);
        }
    }
}

// export worker factory used in src/index
export default function Ckb() {
    return new CkbWorker();
}

if (CONTEXT === 'worker') {
    // Initialize module if script is running in worker context
    const module = new CkbWorker();
    onmessage = module.messageHandler.bind(module);
}
