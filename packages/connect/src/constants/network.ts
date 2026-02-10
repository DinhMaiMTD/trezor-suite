export const TYPES = {
    bitcoin: 'Bitcoin',
    ethereum: 'Ethereum',
    stellar: 'Stellar',
    cardano: 'Cardano',
    ripple: 'Ripple',
    tezos: 'Tezos',
    tron: 'Tron',
    binance: 'Binance',
    solana: 'Solana',
    ckb: 'CKB',
} as const;

export type NetworkType = keyof typeof TYPES;

export const MODULES = [
    'cardano',
    'ckb',
    'ethereum',
    'monero',
    'ripple',
    'solana',
    'stellar',
    'tezos',
    'tron',
] as const;

export type ModuleName = (typeof MODULES)[number];
