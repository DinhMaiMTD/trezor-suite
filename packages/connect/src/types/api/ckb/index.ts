import { Static, Type } from '@trezor/schema-utils';

import { DerivationPath } from '../../params';

export type CKBScript = Static<typeof CKBScript>;
export const CKBScript = Type.Object({
    codeHash: Type.String(),
    hashType: Type.Union([
        Type.Literal('data'),
        Type.Literal('type'),
        Type.Literal('data1'),
        Type.Literal('data2'),
    ]),
    args: Type.String(),
});

export type CKBCellOutput = Static<typeof CKBCellOutput>;
export const CKBCellOutput = Type.Object({
    capacity: Type.String(),
    lock: CKBScript,
    type: Type.Optional(CKBScript),
});

export type CKBOutPoint = Static<typeof CKBOutPoint>;
export const CKBOutPoint = Type.Object({
    txHash: Type.String(),
    index: Type.Number(),
});

export type CKBCellInput = Static<typeof CKBCellInput>;
export const CKBCellInput = Type.Object({
    since: Type.String(),
    previousOutput: CKBOutPoint,
    capacity: Type.Optional(Type.String()),
});

export type CKBCellDep = Static<typeof CKBCellDep>;
export const CKBCellDep = Type.Object({
    outPoint: CKBOutPoint,
    depType: Type.Union([Type.Literal('code'), Type.Literal('dep_group')]),
});

export type CKBTransaction = Static<typeof CKBTransaction>;
export const CKBTransaction = Type.Object({
    version: Type.Number(),
    cellDeps: Type.Array(CKBCellDep),
    headerDeps: Type.Array(Type.String()),
    inputs: Type.Array(CKBCellInput),
    outputs: Type.Array(CKBCellOutput),
    outputsData: Type.Array(Type.String()),
});

export type CKBSignTransaction = Static<typeof CKBSignTransaction>;
export const CKBSignTransaction = Type.Object({
    path: DerivationPath,
    transaction: CKBTransaction,
    network: Type.Optional(Type.String()),
    fee: Type.Optional(Type.Number()),
    chunkify: Type.Optional(Type.Boolean()),
    sphincsplus: Type.Optional(Type.Boolean()),
});

export type CKBSignedTx = Static<typeof CKBSignedTx>;
export const CKBSignedTx = Type.Object({
    signature: Type.String(),
    tx_hash: Type.String(),
});
