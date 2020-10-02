NDN-DIRECT-IND:  A JavaScript client library for Named Data Networking
----------------------------------------------------------------------

NDN-DIRECT-IND is the first native version of the NDN protocol written in JavaScript.  It
implements the NDN packet format.

See the file [INSTALL](https://github.com/operantnetworks/ndn-direct-ind/blob/master/INSTALL)
for build and install instructions.

License
-------
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
A copy of the GNU Lesser General Public License is in the file COPYING.

Overview
--------
Please submit any bugs or issues to the NDN-DIRECT-IND issue tracker:
https://github.com/operantnetworks/ndn-direct-ind/issues

The primary goal of NDN-DIRECT-IND is to provide a pure JavaScript implementation of the NDN API
that enables developers to create browser-based or Node.js-based applications using Named Data Networking.
The approach requires no native code or signed Java applets, and thus can be delivered
over the current web to modern browsers with no hassle for the end user.

Additional goals for the project:
- WebSockets transport for the browser (rather than TCP or UDP, which are not directly supported in
the browser).
- Relatively lightweight and compact, to enable efficient use on the web.

The library currently requires a remote NDN forwarder, and has been tested with NFD from the package
https://github.com/named-data/NFD .

The Javascript API for asynchronous Interest/Data exchange follows the
NDN Common Client Libraries API: https://named-data.net/doc/ndn-ccl-api/ .
This API can be used from the browser or Node.js. The browser version uses
WebSockets for transport. Node.js can use TCP or Unix sockets.

JAVASCRIPT API
--------------

See files in [js/](js/) and examples in [tests/](tests/), [examples/](examples/).

NDN-DIRECT-IND currently supports expressing Interests (and receiving data) and publishing Data
(that answers Interests).  This includes encoding and decoding data packets as well as
signing and verifying them using RSA/EC keys.

### NDN connectivity
The only way (for now) to get connectivity to other NDN nodes is via an NDN forwarder.
JavaScript API in the browser requires NFD's WebSockets transport.
Node.js API can use TCP (remote or local) or Unix sockets (to the local NDN forwarder).

### Including the scripts on a web page
To use NDN-DIRECT-IND in a web page, one of two scripts must be included using a script tag:
`ndn.js` is a combined library; `ndn.min.js` is a compressed version of the combined library
that loads faster but doesn't show the original source for debugging.

For development, see [INSTALL](INSTALL) for instructions on how to build these files.
Or the latest development snapshot can be downloaded from the `build` directory:

- https://github.com/operantnetworks/ndn-direct-ind/raw/master/build/ndn.js
- https://github.com/operantnetworks/ndn-direct-ind/raw/master/build/ndn.min.js

### Examples

**ndnping**

You can check out [examples/ndnping/ndn-ping.html](examples/ndnping/ndn-ping.html) to see how to implement ndnping in NDN.js

**Example to retrieve content**

A simple example of the current API to express an Interest and receive data:

```
var face = new Face();	// connect to a default hub

function onData(interest, data) {
  console.log("Received " + data.getName().toUri());
}

face.expressInterest(new Name("/ndn/org/example/hello.txt"), onData);
```

**Example to publish content**

Publishing content requires knowledge of a routable prefix for your upstream
NDN forwarder.  We are working on a way to either obtain that prefix or use
the `/local` convention.
For now, see [examples/browser/test-publish-async-nfd.html](examples/browser/test-publish-async-nfd.html).
