# Cisco DNA Center - Secure CRT Device Session Generator

*Cisco DNAC Session Generator for SecureCRT*

In large network deployments it can become cumbersome and time consuming to populate and update session files and directory structures in Secure CRT. 

Through the use of various API calls within Cisco DNA Center deployments, the attached script can learn and create sessions and folder hierachy for: 

* Loopback Addresses (Routers and Switches) 
* Management Interface Address (AireOS WLC) 
* Wired Interface IP (Access Points) 
* Gig 0 Out of Band Management Interface (only in detailed mode) 

## Demonstration (Large File May take time to Load):

![Demo](./cisco-dnac-scrt.gif)

### Requirements 

* Secure CRT for OSX (Tested using version 8.5.3)

* Python 2.7 (should be installed by default on OSX)

* Python 'requests' module used for API calls from Secure CRT 

* Network reachability to Cisco DNA Center Version 1.2.5 or higher

* SuperAdmin username and password for Cisco DNA Center (this is the default GUI user if RBAC is not configured)

## Modes of Operation 

The script can be executed in two different modes of operation.

### Quick Mode: 

This mode does not require activation of the 'intent API' and hence does not do a device by device query. This significantly speeds up the discovery and creation of devices, however has the following cavaets: 

* Full Directory Structure Levels are NOT created 
* Devices are discovered and sessions are created in the Cisco DNAC directory only
* For Routers and Switches, only the discovery address (usually loopback) will be used for session creation


### Detailed Mode: 

This mode is more time consuming as it performs per node queries to identify Interface Gig 0/0 ip addressing, so that the device can be reached via other means than just the loopback (discovery address). This is useful for network deployments which may have OOB networks configured to access network devices. 

In detailed mode both discovery address and loopback address are added to the session hierachy. 

Detailed mode also populates the devices within their correct level of the hieracy, such as the site / area or floor. 

### Access Point and Sensors: 

As Access Points and Sensors typically utilize DHCP Addressing, if lease reservations are not statically reserved, the discovery script can be run as needed to re-populate the latest IP Addressing for these devices. 

## Technologies & Frameworks Used

**Cisco Products & Services:**

- Cisco DNA Center 1.2.5 

**Tools & Frameworks:**

- Python (2.7)


## Authors & Maintainers

- Josh Halley <johalley@cisco.com>

## License

This project is licensed to you under the terms of the [Cisco Sample
Code License](./LICENSE).
