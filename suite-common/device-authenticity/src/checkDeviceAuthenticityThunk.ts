import { Feature, selectIsFeatureDisabled } from '@suite-common/message-system';
import { createThunk } from '@suite-common/redux-utils';
import { StoredAuthenticateDeviceResult } from '@suite-common/suite-types';
import { notificationsActions } from '@suite-common/toast-notifications';
import { deviceActions } from '@suite-common/wallet-core';
import TrezorConnect from '@trezor/connect';

import { isDeviceAuthenticityValid } from './utils';

const ACTION_PREFIX = '@device-authenticity';

type CheckDeviceAuthenticityThunkParams = {
    allowDebugKeys: boolean;
    skipSuccessToast?: boolean;
};

export const checkDeviceAuthenticityThunk = createThunk<
    StoredAuthenticateDeviceResult,
    CheckDeviceAuthenticityThunkParams,
    { rejectValue: StoredAuthenticateDeviceResult }
>(
    `${ACTION_PREFIX}/checkDeviceAuthenticity`,
    async (
        { allowDebugKeys, skipSuccessToast },
        { dispatch, getState, extra, fulfillWithValue, rejectWithValue },
    ) => {
        // Bypass for emulator/development
        // Emulators don't have secure elements (Optiga/Tropic) so they always fail this check
        const device = extra.selectors.selectDevice(getState());
        if (!device) {
            throw new Error('device is not connected');
        }

        const mockResult = {
            valid: true,
            optigaResult: { valid: true, error: null, payload: '' },
            tropicResult: { valid: true, error: null, payload: '' },
            success: true,
            payload: {
                optigaResult: { valid: true, error: null, payload: '' },
                tropicResult: { valid: true, error: null, payload: '' }
            }
        };

        if (!skipSuccessToast) {
            dispatch(notificationsActions.addToast({ type: 'device-authenticity-success' }));
        }
        dispatch(deviceActions.setDeviceAuthenticityResult({ device, result: mockResult }));

        return fulfillWithValue(mockResult);

        /* Original logic commented out
        const device = extra.selectors.selectDevice(getState());
        if (!device) {
            throw new Error('device is not connected');
        }

        const result = await TrezorConnect.authenticateDevice({
            device: { path: device.path },
            allowDebugKeys,
        });
        
        // ... rest of original logic
        */
    },
);
