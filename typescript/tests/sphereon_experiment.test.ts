
import { com } from '@sphereon/kmp-mdoc-core';

describe('Sphereon Experiment', () => {
    test('should import com.sphereon.mdoc.data.device.DeviceResponseCbor', () => {
        console.log('com:', com);
        console.log('com.sphereon:', com.sphereon);
        console.log('com.sphereon.mdoc:', com.sphereon.mdoc);
        console.log('com.sphereon.mdoc.data:', com.sphereon.mdoc.data);
        console.log('com.sphereon.mdoc.data.device:', com.sphereon.mdoc.data.device);
        
        expect(com).toBeDefined();
        expect(com.sphereon).toBeDefined();
        expect(com.sphereon.mdoc).toBeDefined();
        expect(com.sphereon.mdoc.data.device.DeviceResponseCbor).toBeDefined();
    });
});
