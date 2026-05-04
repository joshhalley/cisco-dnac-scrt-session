# Cisco Catalyst Center / Cisco DNA Center - SecureCRT Device Session Generator

*Cisco Catalyst Center Session Generator for SecureCRT*

In large network deployments it can become cumbersome and time consuming to populate and update session files and directory structures in SecureCRT.

Through the use of various API calls within Cisco Catalyst Center deployments, the attached script can learn and create sessions and folder hierarchy for:

* Loopback Addresses (Routers and Switches) 
* Management Interface Address (AireOS WLC) 
* Wired Interface IP (Access Points) 
* Gig 0 Out of Band Management Interface (only in detailed mode) 

## Demonstration (Large File May take time to Load):

![Demo](./cisco-dnac-scrt.gif)

### Requirements 

* SecureCRT 9.0 or later with a SecureCRT-supported Python 3.x engine

* Python 3.x installed where SecureCRT can load it

* Python `requests` module installed in the Python 3 environment used by SecureCRT

* Network reachability to Cisco Catalyst Center / Cisco DNA Center with the REST API bundle enabled

* SuperAdmin username and password for Catalyst Center (this is the default GUI user if RBAC is not configured)

### Catalyst Center API Paths

The script uses the current public Catalyst Center API prefixes:

* `POST /dna/system/api/v1/auth/token`
* `GET /dna/intent/api/v1/network-device`
* `GET /dna/intent/api/v1/site-health`
* `GET /dna/intent/api/v1/device-detail`
* `GET /dna/intent/api/v1/interface/network-device/{deviceId}/interface-name`

## Modes of Operation 

The script can be executed in two different modes of operation.

### Quick Mode: 

This mode does not perform a device-by-device detail query. This significantly speeds up the discovery and creation of devices, however has the following caveats:

* Full Directory Structure Levels are NOT created 
* Devices are discovered and sessions are created in the root generated session directory only
* For Routers and Switches, only the discovery address (usually loopback) will be used for session creation


### Detailed Mode: 

This mode is more time consuming as it performs per-node queries to identify Interface Gig 0/0 IP addressing, so that the device can be reached via other means than just the loopback (discovery address). This is useful for network deployments which may have OOB networks configured to access network devices.

In detailed mode both discovery address and loopback address are added to the session hierarchy.

Detailed mode also populates the devices within their correct level of the hierarchy, such as the site / area or floor.

### Access Point and Sensors: 

As Access Points and Sensors typically utilize DHCP Addressing, if lease reservations are not statically reserved, the discovery script can be run as needed to re-populate the latest IP Addressing for these devices. 

## Technologies & Frameworks Used

**Cisco Products & Services:**

- Cisco Catalyst Center / Cisco DNA Center REST APIs

**Tools & Frameworks:**

- Python 3.x
- requests (module)


## Authors & Maintainers

- Josh Halley <johalley@cisco.com>

## License

This project is licensed to you under the terms of the [Cisco Sample
Code License](./LICENSE).
