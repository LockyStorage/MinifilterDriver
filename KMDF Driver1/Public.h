/*++

Module Name:

    public.h

Abstract:

    This module contains the common declarations shared by driver
    and user applications.

Environment:

    user and kernel

--*/

//
// Define an Interface Guid so that apps can find the device and talk to it.
//

DEFINE_GUID (GUID_DEVINTERFACE_KMDFDriver1,
    0x87e6d7da,0xae3a,0x4185,0x8f,0xd3,0x2a,0x43,0x7b,0xac,0x55,0x9c);
// {87e6d7da-ae3a-4185-8fd3-2a437bac559c}
