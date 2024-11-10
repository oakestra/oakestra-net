# eBPF Manager for NetManager

The **eBPF Manager** enables the dynamic management of so-called eBPF modules within the NetManager. eBPF modules are lightweight, eBPF-based plugins that can be developed independently of Oakestra, implementing Virtual Network Functions (VNFs) such as proxies or firewalls. This approach enables the Oakestra Networking component to be extended or optimized as needed, while leveraging of the high performance offered by kernel-level network processing.

For more details: [Leveraging eBPF in Orchestrated Edge
Infrastructures](https://www.nitindermohan.com/documents/student-thesis/BenRiegel_MT.pdf)

## Enabling eBPF Features

The eBPF Manager is part of the experimental features in Oakestra and can be enabled by adding it to a comma-separated list of experimental features in the respective command line flag when starting the NetManager.
```bash
sudo ./NetManager --experimental ebpf
```

## eBPF Manager API
When starting the NetManager with the eBPF experimental flag, the eBPF Manager is initialized and its API is exposed under the `/ebpf` route as part of the NetManager’s API.
#### Get all eBPF Modules
```
GET /ebpf
Content-Type: None
```
#### Get a specific eBPF Module by ID
```
GET /ebpf
Content-Type: None
```
#### Create a new Instance of an eBPF Module
```
POST /ebpf
Content-Type: application/json
Body:
{
"name": "<module name>",
"config": {...}
}
```
#### Delete all eBPF Modules
```
DELETE /ebpf
Content-Type: None
```
#### Delete an eBPF Module by ID
```
DELETE /ebpf/<id>
Content-Type: None
```
#### eBPF Module Subroutes
An eBPF Module can register a subroute within the eBPF Manager’s
API during its initialization. These subroutes are registered under:
`/ebpf/<eBPF Module ID>`
A typical flow begins with initializing an eBPF module via a POST request to `/ebpf`. The
response will include an ID that can be extracted to access the API of the eBPF Module.

## What is eBPF?
[Extended Berkeley Packet Filter](https://en.wikipedia.org/wiki/EBPF) (eBPF) is a Linux technology that allows code to be dynamically loaded and executed in the kernel. It combines the flexibility of user-space applications with the performance of kernel applications, making it particularly well-suited for writing programs that handle network packets with high efficiency.
