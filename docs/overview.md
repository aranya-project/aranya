**ARANYA OVERVIEW**

Table of Contents

- [What is Aranya?](#what-is-aranya)
- [What can I use Aranya for?](#what-can-i-use-aranya-for)
- [What does Aranya mean for me?](#what-does-aranya-mean-for-me)
    - [Capabilities](#capabilities)
- [Aranya Platform](#aranya-platform)
  - [Deployment Ecosystem](#deployment-ecosystem)
- [Integration/API Overview](#integrationapi-overview)
  - [Aranya APIs](#aranya-apis)
    - [Configuration File API](#configuration-file-api)
    - [Initialization API](#initialization-api)
    - [Access Control APIs](#access-control-apis)
    - [Data Exchange APIs](#data-exchange-apis)
    - [Transport APIs](#transport-apis)
- [Glossary](#glossary)

# What is Aranya?

Aranya is an **access governance and secure data exchange platform for organizations to control their critical data and services**. Access governance is a mechanism to define, enforce, and maintain the set of rules and procedures to secure your system\'s behaviors. Data governance is a more narrowed approach for applying the same mechanism to specifically address access permissions of all data in the system.

Aranya ensures that your system\'s process for managing access controls to data or services is aligned with your organization\'s objectives and adheres to policy requirements. Defining the set of policies by specifying roles and permissions enables you to **safeguard sensitive information, maintain compliance, mitigate the risk of unauthorized data exposure, and grant appropriate access.** Aranya\'s decentralized platform allows you to define and enforce these sets of policies to secure and access your resources.

The platform is **delivered and integrated into your system as a library** for policy-driven access controls and secure data exchange. The library is deployed on endpoints, integrating into applications which require granular access controls over their data and services. Endpoints can entrust Aranya with their data protection and access controls so that other applications running on the endpoint need only to focus on using the data for their intended functionality.

A key discriminating attribute of Aranya is the decentralized, zero trust architecture. Through the integration of the library, access governance is implemented without the need for a connection back to centralized IT infrastructure. With Aranya\'s decentralized architecture, if two endpoints are connected to each other, but not back to the cloud or centralized infrastructure, **governance over data and applications will be synchronized between peers** **and further operations will continue uninterrupted.**

# What can I use Aranya for?

-   **Secure Sensitive Data:** Ensure your data is secured from unauthorized access or potential breaches using cryptographic algorithms to encrypt the data.

-   **Data Protection and Privacy:** Granular controls which can grant or revoke access, defined through policy that dictate whether an entity can or can\'t access data.

-   **Secure Data Exchange:** Enable unidirectional or bidirectional secure data exchange between two users without the need for access to any form of centralized IT infrastructure.

-   **Data Integrity/Provenance:** Access activity logs provide transparency on data\'s integrity, ensuring your data has not been compromised or manipulated.

-   **Effective Incident Response:** In the event of a security incident, access governance facilitates effective incident responses with audit trails and access activity logs.

-   **Clear Accountability Structures:** Align access permissions with authenticated entities identities, ensuring individuals are accountable for actions within their scope.

-   **Adherence to Industry Regulations and Compliance:** Meet Zero Trust and other data access policy requirements, such as the DoD Zero Trust Strategy.

-   **Streamlined Access Management:** Automate and streamline access management processes, decreasing the burden on IT and ensuring efficient onboarding and offboarding processes.

-   **Cost Reduction through Automation:** Automating your data access governance accelerates workflows but also reduces operational costs associated with manual access management.

# What does Aranya mean for me?

Aranya is a software library that is deployed on an **endpoint** to securely manage data and access controls. Each endpoint can be a piece of hardware (e.g. spacecraft payload, drone, cellular device, etc.) or software (e.g. application). An **instance** is a single deployment of the Aranya software on a given endpoint, and each endpoint can have one or many instances deployed on it.

An **entity,** which can also be referred to as a user, is used to identify an instance by assigning it a set of cryptographic keys used for identity, authorization, and authentication allowing it to govern the behavior of the endpoint. A **policy** is written to define these behaviors, accepted actions with corresponding commands, that will be generated.

### Capabilities

Aranya provides the following capabilities in a single, low size, weight, and power (SWAP) software platform, key to your organization\'s access governance:

-   **Identity & Access Management (IdAM)**

    -   **RBAC (Roles):** Entities, or a group of entities, are given permission to interact with data or applications based on pre-defined roles.

    -   **ABAC (Attributes):** Entities, or a group of entities, can be given permission to interact with data or applications based on dynamic attributes.

    -   **Revocation:** Entities or whole RBAC/ABAC roles can be removed from access just as easily as it is to grant access.

-   **Decentralized Peer-to-Peer Messaging**

    -   Enable secure data exchange between two endpoints without the need for access to any form of centralized IT infrastructure.

-   **Key Management**

    -   Aranya leverages the crypto module that is implemented and configured on the endpoint to perform cryptographic functions used by policy commands. This means that an authority model can be designed to utilize the crypto module for generating, storing, and/or distributing cryptographic keys securely and in accordance with the governing policy, enabling dynamic key management.

-   **Data Segmentation**

    -   Data can be segmented based on pre-defined roles or attributes through topic labels. For example, certain roles may be restricted from gaining access to a topic and other roles may be prerequisites for gaining access. In addition to roles, any attribute stored about the entity may be used to control access to a topic.

-   **Audit Log of Immutable Commands**

    -   Using the Control Plane (described below), Aranya provides a high-assurance audit log of all commands, or instructions given by an entity to perform a specific task, providing data integrity and provenance for the movement of your data throughout your infrastructure.

    -   The native data structure _is_ the audit log of all commands. The log, which is distributed and synchronized across all endpoints, provides a cryptographically authenticated, tamper-evident, high-assurance replication of all commands taken.

    -   For each verified command, a cryptographic hash is created. If a previous event has been modified, the current one will no longer be valid due to the hash changing.

# Aranya Platform

## Deployment Ecosystem

The Aranya platform is hardware and software agnostic and is designed to be built for a wide variety of platforms. Deployed as a library, the software makes no hardware or software assumptions. The software is serverless and asynchronous. The software is also link-agnostic, meaning it works with any transport protocol over trusted (single) or mixed (multiple) networks.

**Designed for Embedded Device Support**

-   Lightweight platform: \<1.5 MB Binary and \<1.5 MB RAM

-   100% built in Rust, a safety-first, high-level programming language

    -   **Safety:** Rust's borrow checker ensures memory safety without the overhead of garbage collection. This means fewer memory leaks and crashes.

    -   **Performance:** Comparable to C and C++, Rust provides fine-grained control of memory and other resources.

**Supported Platforms**

-   Linux

-   ARM 32/64, x86

# Integration/API Overview

Aranya provides additional utilities and APIs for ease of integration. These are all outlined below, though the API documentation for each can be found in separate documentation per request.

## Aranya APIs

### Configuration File API

This API will load the configuration file and set up the environment using configured parameters. The configuration file provides information for all dependencies, to include encryption.

### Initialization API

This API provides the initialization of:

1.  Crypto Module

    -   API provides a means to attach cryptographic modules into Aranya. For example, a FIPS-certified cryptographic module, or a hardware security or cryptographic acceleration module.

2.  Assignment of Crypto Keys to Entities

3.  Network transport

    -   API provides a means to attach transport modalities to Aranya.

### Access Control APIs

Enables the functionality defined within the policy, allowing enforcement of identity management, roles and rules. This includes the APIs that relate to capabilities within the policy actions and commands.

### Data Exchange APIs

> **Off-Graph Data Exchange API**
>
> Provides an off-graph, real-time message-passing API with end-to-end encryption.
>
> **On-Graph Data Exchange API**
>
> Provides an on-graph message-passing API for guaranteed data delivery with end-to-end encryption.

### Transport APIs

Transport API uses the appropriate Aranya protocol to process communications between two endpoints. Endpoints must synchronize their state to allow peers to exchange commands and update the DAG, if on-graph data exchange API is called, with newly received commands. An entity must request their peer to sync by sending them a snapshot of their DAG, to which the peer responds with the set of commands that the entity is missing. If the peer suspects they are missing some commands which the peer entity has, they can issue a sync request in return.

If the off-graph data exchange API is called, then Aranya will use the appropriate encryption/decryption keys to send and receive data between endpoints, leveraging the network protocol configured.

# Glossary

-   **Action:** An action is a generated function defined in the policy language that can affect state. Actions create new commands to be evaluated by the policy and, if valid, added to the graph. Actions can be thought of as providing a contract (along with effects) to the application which is implemented by the policy.

-   **Attribute-based Access Control (ABAC):** A version of Identity Access Management that uses attributes over defined roles to grant an entity or group of entities\' permission(s) to interact with a graph.

-   **Audit and Monitoring**: A tool to review and monitor activities and detect suspicious behavior.

-   **Command:** Instruction given by an entity to perform a specific task. It is the object that is sent and stored to denote individual actions by different entities, as defined possible by the policy. For example, it could be to add an entity to a team, whereby the command object itself indicates the action that was performed and other necessary information, such as the credentials of the newly added entity.

-   **Directed Acyclic Graph (DAG):** A directed graph with no directed cycles. That is, a graph of vertices and edges, with each edge directed from one vertex to another, such that following those directions will never form a closed loop.

-   **Endpoint:** Where the Aranya software library is deployed. This can be a piece of hardware (e.g. spacecraft payload, drone, cellular device, etc.) or software (e.g. application).

-   **Entity:** Represents an instance and has an identity associated to it, as well as other crypto material which govern how it behaves on the endpoint. An entity could be used to describe a specific user on the platform.

-   **Graph**: Data structure of stored commands, where each command is connected by a line to the command that occurred immediately before it, as seen from the client\'s local state.

-   **IdAM**: (as defined by DOD): The combination of technical systems, policies and processes that create, define, and govern the utilization, and safeguarding of identity information.

-   **Instance:** Individual deployment of the Aranya library. A single endpoint can have one or many instances.

-   **Peer to Peer**: Allows computers to share access by acting as a server for each other.

-   **Policy**: A written document that defines all the permitted actions, commands, effects, validity checks, side-effects, facts, etc. Policies are customizable documents written in the domain specific language of the _Policy_ _Language_,

-   **Revocation**: Removal of access to a specific data set.

-   **Role-based Access Control (RBAC):** A version of Identity Access Management that uses roles to grant a user or group of users\' permission(s) to interact with a graph.

-   **Segmentation**: Chunking specific data as part of processes.

-   **Secure Authentication and Authorization:** Strong authentication methods and controls which limit access to authorized individuals.

-   **State:** All the information that defines how the software platform is currently functioning, how it can change, and how it should behave in different scenarios

-   **QUIC:** Quick UDP Internet Connections (QUIC) is a communication protocol built on top of the User Datagram Protocol (UDP) and uses encryption and multiplexing to make data transfer faster and more secure.

-   **UDP:** User Datagram Protocol (UDP) is a communication protocol that allows endpoints and applications to send data across a network without establishing a connection first.

-   **Zero-Trust:** A cybersecurity approach that requires all entities and devices to be authenticated and authorized before accessing data, endpoints, applications, and services.
