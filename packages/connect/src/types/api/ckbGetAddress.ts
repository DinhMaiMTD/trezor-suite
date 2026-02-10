import type { Address, BundledParams, GetAddress, Params, Response } from '../params';

export declare function ckbGetAddress(params: Params<GetAddress>): Response<Address>;
export declare function ckbGetAddress(params: BundledParams<GetAddress>): Response<Address[]>;
