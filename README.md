GoRadius
========

GoRadius is a Go Library implementing the RADIUS protocol. It provides functions for Marshalling & Unmarshalling RADIUS packets. The packet processing logic resides with the application using the library.

**NOTE**: This is a Work-In-Progress. A lot of will change in the coming weeks, and I recommend against using this in production code as API might change. Patches are welcome!

Dictionaries
------------

GoRadius requires two kinds of dictionaries to function: a RADIUS dictionary containing Attribute-Value-Pairs (AVP) that are assigned by various RFCs and a Vendor Dictionary, which documents Vendor-specific extensions to the protocol. GoRadius includes samples of these user-extensible dictionaries under the dict/ directory. 

Locations of these dictionary files must be given during initialization of the library, as they are needed to parse & decode the data received. 

API
---

The first API exposed by GoRadius is the Parser Registration API ```RegisterParser```. This allows the developer to register a custom parser for a specific AVP, not supported by default by the library. A Parser has a name, for reference, which must match the parser name given in the dictionary file. If GoRadius encounters that specific AVP, it will callback the function registered with the raw bytes of content, expecting in return the parsed content in interface{} format.

When operating in UDP Server mode, the library must be provided with a Shared-Secret Callback function. This function is called when the RADIUS server must authenticate a NAS sending packets to RADIUS. The library will provide the IP address of the callee, expecting in return the shared-secret as a plain-text string.

An example of how the above API functions are used is in the goradius_test.go file.

LICENSE
-------

This library is under Apache License, Version 2.0. For more details please see LICENSE file.

Copyright
---------

Copyright (C) 2013 Andreas Louca. All rights reserved.
