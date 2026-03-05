import { Static, Type } from '@trezor/schema-utils';

import type { Address, BundledParams, Params, Response } from '../params';
import { GetAddress as GetAddressShared } from '../params';

export type CkbGetAddress = Static<typeof CkbGetAddress>;
export const CkbGetAddress = Type.Composite([
    GetAddressShared,
    Type.Object({
        network: Type.Optional(Type.String()),
        coin: Type.Optional(Type.String()),
        sphincsplus: Type.Optional(Type.Boolean()),
    }),
]);

export declare function ckbGetAddress(params: Params<CkbGetAddress>): Response<Address>;
export declare function ckbGetAddress(params: BundledParams<CkbGetAddress>): Response<Address[]>;
