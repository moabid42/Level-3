# Defensive Fortress

## Table of Contents

1. [Overview & Objectives](#overview--objectives)
2. [Prerequisites](#prerequisites)
3. [Architecture & Design](#architecture--design)

   * [Network Diagram](#network-diagram)
   * [Host Inventory & Roles](#host-inventory--roles)
   * [Security Policies Summary](#security-policies-summary)
4. [Part 1 – Infrastructure Setup](#part-1--infrastructure-setup)

   * [Overview](#overview-1)
   * [Prerequisites](#prerequisites-1)
   * [Tasks](#tasks)

     * [OS Installation & Hardening](#os-installation--hardening)
     * [Network Isolation & Firewalling](#network-isolation--firewalling)
     * [Load Balancer & Application Deployment](#load-balancer--application-deployment)
     * [WireGuard Private Network](#wireguard-private-network)
     * [Ansible Automation](#ansible-automation)
   * [Deliverables](#deliverables-for-part-1)
5. [Part 2 – Logging & Alerting](#part-2--logging--alerting)

   * [Overview](#overview-2)
   * [Prerequisites](#prerequisites-2)
   * [Tasks](#tasks-1)

     * [Select Logging Stack](#select-logging-stack)
     * [Central Logging Server Setup](#central-logging-server-setup)
     * [Log Shipper Configuration on Hosts](#log-shipper-configuration-on-hosts)
     * [Indexing & Dashboards](#indexing--dashboards)
     * [Alerting & Alarms](#alerting--alarms)
     * [Testing & Demonstration](#testing--demonstration-1)
   * [Deliverables](#deliverables-for-part-2)
6. [Part 3 – Permissions & Access Control](#part-3--permissions--access-control)

   * [Overview](#overview-3)
   * [Prerequisites](#prerequisites-3)
   * [User Categories & Requirements](#user-categories--requirements)

     * [Developers](#developers)
     * [IT-Admin](#it-admin)
     * [Extern](#extern)
   * [Tasks](#tasks-2)

     * [User & Group Creation](#user--group-creation)
     * [Sudoers Configuration](#sudoers-configuration)
     * [SSH Hardening](#ssh-hardening)
     * [Zero-Trust Principles](#zero-trust-principles)
     * [Testing & Validation](#testing--validation)
   * [Deliverables](#deliverables-for-part-3)
7. [Part 4 - Extra Mile: Honeypots](#part-4---extra-mile-honeypots)
8. [How to Use This README](#how-to-use-this-readme)
9. [Notes](#notes)

## Overview & Objectives

The Defensive Fortress project for “ctfSec GmbH” involves deploying and securing the [CTFd](https://github.com/CTFd/CTFd) application in a high-availability infrastructure using Rocky Linux. Students will practice OS hardening, network isolation, SSL/TLS configuration, private connectivity with WireGuard, centralized logging and alerting, least-privilege access controls, and honeypot deployment. The objective is to design, automate, deploy, and secure each component following best practices and zero-trust principles.

This README covers Part 1 (Infrastructure Setup), Part 2 (Logging & Alerting), and Part 3 (Permissions & Access Control) for the Defensive Fortress project. It provides instructions, tasks, and guidance for students to implement each part. Inventory & Host Roles details are omitted.

---

## Part 1 – Infrastructure Setup

### Overview

In this part, you will provision and configure Rocky Linux servers, enforce network isolation, deploy the [CTFd](https://github.com/CTFd/CTFd) application behind a load balancer with SSL/TLS, set up private connectivity via WireGuard, and automate the process using Ansible.

### Prerequisites

* Familiarity with Linux administration and shell.
* Ansible installed on your control machine (optional; you can also provision/configure manually or with alternative tools/scripts).
* Virtualization environment (e.g., Vagrant + VirtualBox) or cloud account to spin up Rocky Linux instances.
* Git for version control.
* SSH key pair for access to servers.

### Tasks

#### OS Installation & Hardening

* Install Rocky Linux on all target servers.
* Apply basic hardening via Ansible:

  * Ensure minimal packages; remove unused services.
  * Enable SELinux in enforcing mode; adjust policies if needed.
  * Configure sysctl for security (disable IP forwarding unless needed, protect against spoofing).
  * Set up firewall rules (firewalld or iptables) to allow only required ports.
  * Configure time synchronization (chrony).
  * Install and configure intrusion prevention (e.g., fail2ban).
  * Automate regular updates via Ansible tasks.


#### Network Isolation & Firewalling

* Design network segmentation: define subnets or VM networks to isolate roles.
* Configure strict firewall rules per host role:

  * Application servers: accept traffic only from the load balancer on application port.
  * Load balancer: accept public HTTPS (443) and forward to application servers.
  * Logging server: accept log shipping only from known hosts; management access only via WireGuard.
  * Honeypot (if present): placed in isolated network with limited outbound.
* Document firewall rules in Ansible tasks (e.g., ansible.posix.firewalld) and in code comments/templates.

#### Load Balancer & Application Deployment

* Review [CTFd README](https://github.com/CTFd/CTFd) for prerequisites and deployment steps. Clone the CTFd repository, install required dependencies (Python, plugins, etc.), and prepare for deployment.
* Choose load balancer software (HAProxy, Nginx, or Traefik).

  * Configure frontend listening on HTTPS (port 443) with SSL/TLS termination.
  * Configure backends pointing to two application server instances, with health checks.
  * Automate certificate issuance:

    * For public domain: use Let’s Encrypt and certbot in Ansible.
    * For lab: create a self-signed CA and distribute trust to your workstation.
  * Optionally redirect HTTP (80) to HTTPS.
* Automate CTFd deployment on each app server optionally via Ansible or manually/scripted approach:

  * Clone the repository.
  * Install dependencies (Python, pip packages, database client).
  * Configure environment variables or config files (database credentials, secret keys).
  * Set up database (MySQL/MariaDB/PostgreSQL) according to CTFd requirements.
  * Create a systemd service unit for CTFd; ensure idempotency and handlers to restart on change.
* Test high availability: simulate one server down; verify load balancer routes to the other.
* Add rate limiting to your Load balancer.

> Make sure you have only one central DB

#### WireGuard Private Network

* Install WireGuard on servers designated for management access and on your control machine.
* Define a private subnet (e.g., 10.0.100.0/24) for admin connections.
* Configure WireGuard server (on a designated host) and clients (your workstation, logging server, etc.).
* Automate key generation and distribution via Ansible Vault or secure methods.
* Ensure management interfaces (SSH, logging UI) are only accessible via WireGuard.
* Document how to connect from your local machine: provide instructions in README.

#### Ansible Automation

> This part is optional if you are gonna develop your own scripts

* Structure roles for modularity:

  * Common hardening
  * Rocky Linux specific tweaks
  * Firewall configuration
  * Load balancer configuration
  * CTFd deployment
  * WireGuard setup
  * Logging agent installation
* Use variables for IPs, ports, paths, certificate details.
* Use Jinja2 templates for configuration files (e.g., load balancer, WireGuard).
* Ensure playbooks are idempotent; handle errors gracefully.
* Secure sensitive data (private keys) via Ansible Vault.
* Provide a top-level playbook orchestrating execution order (e.g., hardening before service deployment).

### Deliverables for Part 1

* Ansible playbooks and roles for OS hardening, network rules, load balancer, CTFd deployment, and WireGuard.
* Configuration templates (Jinja2) for firewall, load balancer, and WireGuard.
* Instructions in README for running the playbooks and accessing deployed CTFd via HTTPS.
* Evidence of HA and network isolation (screenshots or logs showing connectivity restrictions).
* Brief explanation of chosen design decisions in README comments or separate section.

---

## Part 2 – Logging & Alerting

### Overview

Implement a centralized logging solution to collect system, CTFd application, and honeypot logs, process and index them for searching/visualization, and configure alerts for suspicious activity.

### Prerequisites

* Basic knowledge of logging stacks (ELK: Elasticsearch, Logstash/Filebeat, Kibana) or alternative OSS SIEM (Wazuh, Graylog).
* Ansible for automation (optional; manual or scripted approaches acceptable).
* WireGuard or internal network access to the logging server.

### Tasks

#### Select Logging Stack

* Choose between:

  * ELK Stack (Elasticsearch + Filebeat + Kibana).
  * OSS SIEM alternatives (Wazuh with Elastic, Graylog).
  * Splunk (if available).
* For lab, ELK with Filebeat is recommended.

#### Central Logging Server Setup

* Automate installation of Elasticsearch and Kibana (directly or via Docker/containers) using Ansible.
* Secure access: restrict Kibana UI to WireGuard network or internal subnet; require authentication.
* Configure resource limits according to lab environment.

#### Log Shipper Configuration on Hosts

* Install Filebeat (and Metricbeat if metrics desired) on each server via Ansible.
* Configure Filebeat to collect:

  * System logs (journal or /var/log/messages).
  * SSH logs (/var/log/secure or equivalent).
  * CTFd application logs: configure path according to CTFd logging (e.g., CTFd logs directory).
  * Honeypot logs: configure path if honeypot deployed.
* Use tags/fields to identify host roles (e.g., `role: app`, `role: honeypot`).
* Secure communication: use TLS between Filebeat and Elasticsearch or ship to Logstash.

#### Indexing & Dashboards

* In Kibana, define index patterns (e.g., `filebeat-*`).
* Create dashboards showing:

  * System metrics: CPU, memory, disk usage (if Metricbeat used).
  * SSH login attempts (success/failure over time).
  * CTFd application errors or key events (e.g., user registrations, challenge submissions).
  * Honeypot interactions.
* Document steps in README for accessing Kibana and exploring dashboards.

#### Alerting & Alarms

* Define alert rules using available mechanisms:

  * Elasticsearch Watcher (if licensed) or open-source alternatives like ElastAlert, Kibana Alerts in OSS, or simple scripts.
* Example alerts:

  * Multiple failed SSH logins in short period (indicates brute force).
  * Unusual root or sudo usage.
  * New user creation events.
  * CTFd error rate spike or suspicious activity patterns.
  * Honeypot connection event triggers immediate alert.
* Configure notification methods (email, Slack webhook), or simulate alerts by logging to a file or output in Kibana.
* Automate alert rule deployment via Ansible where possible.

#### Testing & Demonstration

* Generate test logs: simulate failed SSH attempts; generate CTFd application errors or test submissions; trigger honeypot connections.
* Verify logs appear in Kibana dashboards.
* Confirm alert rules fire and notifications are delivered or visible.
* Document test procedures and results in README.

### Deliverables for Part 2

* Ansible roles/playbooks for logging server setup and Filebeat configuration on hosts.
* Kibana index patterns and example dashboard JSON exports (optional) or instructions to recreate dashboards.
* Alert rule definitions and instructions for deployment.
* README sections explaining how to access logging UI, trigger tests, and interpret alerts.
* Sample evidence: screenshots or log excerpts showing alerts and dashboards.

---

## Part 3 – Permissions & Access Control

### Overview

Define and enforce least-privilege access for three user categories (developers, IT-admins, extern), apply zero-trust principles, and harden SSH and sudo configurations.

### Prerequisites

* Understanding of Linux user/group management, SSH configuration, and sudoers syntax.
* Ansible for automating user and permission setup (optional; manual configuration acceptable).

### User Categories & Requirements

#### Developers

* Access:

  * Read/write to application code repository.
  * Ability to deploy or test changes in non-production/staging.
  * **No root** on production app servers.
* Implementation:

  * Create `developers` group.
  * Use a `deploy` user or CI pipeline account for deployments; restrict via sudoers to only necessary commands (e.g., restart CTFd service).
  * Do not permit SSH direct access to production app servers; if required, restrict commands via `ForceCommand` or specialized scripts.

#### IT-Admin

* Access:

  * Manage infrastructure (install packages, view logs), but **no full root**.
  * Access logging data for troubleshooting via Kibana or limited shell access.
* Implementation:

  * Create `itadmin` group.
  * Configure sudoers to allow specific commands (e.g., `journalctl`, `systemctl restart <services>`, package installation) without full root.
  * Restrict SSH access to management network via WireGuard.
  * Log all sudo attempts and monitor.

#### Extern

* Access:

  * Minimal limited operations on servers (e.g., fetch specific logs or run a script).
  * SSH key-based access only; no password.
* Implementation:

  * Create `extern` group.
  * Use `authorized_keys` with `command="..."`, or restricted shell (`rbash`) or `ForceCommand` to limit allowed operations.
  * No sudo privileges.
  * Require connection via a bastion host or WireGuard if appropriate.

### Tasks

#### User & Group Creation

* Via Ansible, create groups: `developers`, `itadmin`, `extern`.
* For each sample user, add SSH public keys to `~/.ssh/authorized_keys` with appropriate options (e.g., `from=` restrictions).
* Use Ansible Vault or secure storage for public keys.

#### Sudoers Configuration

* Create `/etc/sudoers.d/` entries for each group.
* For `developers`: allow only specific commands (e.g., restart CTFd service, deploy scripts).
* For `itadmin`: allow selected administrative commands (e.g., viewing logs, restarting services, installing approved packages). Avoid blanket `ALL`.
* For `extern`: no sudo privileges.
* Ensure `NOPASSWD` only for necessary commands; document rationale.
* Validate sudoers syntax via `visudo --check` in Ansible tasks.

#### SSH Hardening

* In `/etc/ssh/sshd_config`, apply:

  * `PasswordAuthentication no`.
  * `PermitRootLogin no`.
  * `AllowGroups developers itadmin extern` (or more restrictive per host role).
  * Use `Match Address` or `authorized_keys from=` to restrict login sources (e.g., only WireGuard IPs).
  * For `extern`, use `ForceCommand` or restricted shell to allow only designated operations.
* Reload SSH service via Ansible handlers after config changes.

#### Zero-Trust Principles

* Require all admin connections over WireGuard or bastion.
* Log and audit all actions: enable sudo logging, consider auditd for critical file changes.
* Enforce least privilege by granting only the minimal commands users need.
* Rotate SSH keys periodically; document procedure for key rotation.
* Consider session recording for critical operations (optional, advanced).

#### Testing & Validation

* For each group:

  * Attempt allowed operations and verify success.
  * Attempt forbidden operations and verify failure and audit log entry.
* Document test cases and results in README.

### Deliverables for Part 3

* Ansible roles/playbooks to create users/groups, configure sudoers, and harden SSH.
* SSH configuration templates showing restrictions.
* Sample public key management approach (e.g., directory of keys or Ansible Vault references).
* README sections with instructions on testing access controls, example commands, and expected outcomes.
* Evidence of logs showing blocked attempts or sudo usage.

---

## Part 4 - Extra Mile: Honeypots


### Overview

As an optional challenge, deploy a simple honeypot to simulate a vulnerable system and monitor attacker behavior.

### Tasks

* Choose a basic honeypot such as [Cowrie](https://github.com/cowrie/cowrie) (SSH/Telnet) or [Dionaea](https://github.com/DinoTools/dionaea) (malware collection).
* Deploy it on a dedicated VM (e.g., `honeypot1`) in a DMZ or isolated network segment.
* Restrict outbound network access: only allow logging connections to your central log server (`log1`).
* Collect logs from honeypot and ship them to Elasticsearch/Kibana or your SIEM.
* Tag entries as `source: honeypot` to separate from production logs.

### Deliverables

* Minimal setup script or steps for the honeypot.
* One log sample showing attacker interaction.
* Dashboard screenshot or note showing honeypot logs visible in central logging.

---

## Notes

* Adapt IP addresses, domain names, and environment specifics to your setup.
* Store sensitive data (private keys) securely; do not commit them to public repositories.
* Ensure idempotency in Ansible: rerunning playbooks should not cause unintended changes.
* Keep a security mindset: validate firewall rules, access restrictions, and monitor logs continuously.

Good luck with your Defensive Fortress project!


---

## Architecture & Design

### Network Diagram

Include a diagram (e.g., draw\.io / diagrams.net) showing:

* **Public Internet** → **Load Balancer (lb1)**
* **Private Subnet** containing **Application servers (app1, app2)**
* **Management Network / WireGuard**: main workstation ↔ management interface on each host
* **Logging Server (log1)**: reachable only via WG or private network from known hosts
* **Honeypot Network** / DMZ: honeypot1 with limited outbound, logs shipped to log1

*(Place the diagram file in `docs/network-diagram.png` or similar, and reference here.)*

### Host Inventory & Roles

Define host names, roles, and primary IPs (example):

| Hostname  | Role                           | Network(s)                              | Notes                                          |
| --------- | ------------------------------ | --------------------------------------- | ---------------------------------------------- |
| lb1       | Load Balancer                  | Public-facing NIC; private NIC to apps  | HAProxy/Nginx front-end, SSL/TLS termination   |
| app1      | App Server                     | Private NIC only                        | Runs CTFd application                          |
| app2      | App Server                     | Private NIC only                        | Runs CTFd application                          |
| log1      | Logging Server                 | Private NIC; optionally WG-only access  | Runs Elasticsearch & Kibana (or chosen SIEM)   |
| honeypot1 | Honeypot                       | Public-facing honeypot NIC; private NIC | Runs Cowrie (SSH honeypot)                     |
| bastion   | (Optional) Bastion / Jump Host | Public & WG/Private NIC                 | For extern users; restricted shell environment |

> **Note:** IP addresses and subnets should be defined per environment. Use variables in Ansible. E.g.,
>
> * Public subnet: e.g., DHCP or static public IP for lb1 (cloud) or NAT forwarded port (local).
> * Private subnet: e.g., 10.0.1.0/24 for app servers & log server.
> * WireGuard network: e.g., 10.0.100.0/24.

### Security Policies Summary

* **Firewall rules:**

  * lb1: allow inbound HTTPS (443) from anywhere; allow SSH only from management/WG or trusted IP.
  * app servers: allow traffic only from lb1 on application port; SSH only via WireGuard.
  * log server: accept log-shipping only from known hosts; SSH/management only via WireGuard.
  * honeypot: allow inbound on honeypot service port(s); block outbound except to log server for shipping logs.
* **SELinux:** enforcing on all hosts; custom policy modules only if required.
* **SSH:**

  * PasswordAuthentication no; PermitRootLogin no; allow only group-based SSH; restrict via `Match` or `from=` where needed.
* **Users & Groups:**

  * Groups: `developers`, `itadmin`, `extern`.
  * Sudoers: least-privilege commands allowed per group.
* **WireGuard:**

  * Only authorized peers; management traffic encrypted; no leaking of internal networks to public.
* **Logging & Alerting:**

  * Centralized logs in Elasticsearch/Kibana or chosen SIEM; alert rules for suspicious events (e.g., SSH brute force, honeypot hits).
* **Honeypot Isolation:**

  * Honeypot cannot be pivot point; strict egress filtering.
* **Zero Trust Principles:**

  * Authenticate each request; enforce least privilege; continuous monitoring; network segmentation.

---

## How to Use This README

1. **Initialize Your Repository**: Create a Git repository for this project locally. Place this README in the root of that repository. You should commit everything including your playbooks, configuration templates, diagrams, and any scripts alongside this README in the same repo.
2. **Review Prerequisites**: Ensure you have access to a virtualization or cloud environment and Ansible installed (or plan your manual/scripted approach).
3. **Implement Part 1 – Infrastructure Setup**: Follow [Part 1 – Infrastructure Setup](#part-1--infrastructure-setup) instructions. As you develop Ansible playbooks and roles, commit them to your repository.
4. **Proceed to Part 2 – Logging & Alerting**: Deploy your logging stack and configure agents as described in [Part 2 – Logging & Alerting](#part-2--logging--alerting). Commit related code and documentation, make sure to add some screenshots for your tests, and logs.
5. **Implement Part 3 – Permissions & Access Control**: Set up users, groups, SSH hardening, and sudoers configurations per [Part 3 – Permissions & Access Control](#part-3--permissions--access-control). Keep configurations in your repository.
6. **Document Tests and Evidence**: At each stage, document test results, screenshots, log excerpts, and explanations in the repo (e.g., under `docs/` or as Markdown files). Commit these artifacts so I can review.
7. **You are done?**: Send the repo link to moabid.

---

## Notes

* Store sensitive data (private keys) securely; do not commit them to public repositories.
* Ensure idempotency in Ansible: rerunning playbooks should not cause unintended changes. (If used)
* Keep a security mindset: validate firewall rules, access restrictions, and monitor logs continuously. (Anything not used should be removed)

> *Good luck with your Defensive Fortress project!*
