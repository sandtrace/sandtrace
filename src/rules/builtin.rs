use super::schema::{AlertConfig, Detection, DetectionRule};
use crate::event::{AlertChannel, Severity};

pub fn credential_access_rules() -> Vec<DetectionRule> {
    vec![
        DetectionRule {
            id: "cred-access-aws".to_string(),
            name: "AWS Credential File Access".to_string(),
            severity: Severity::High,
            description: "Non-standard process accessing AWS credentials".to_string(),
            detection: Detection {
                file_paths: vec![
                    "~/.aws/credentials".to_string(),
                    "~/.aws/config".to_string(),
                ],
                excluded_processes: vec![
                    "aws".to_string(),
                    "terraform".to_string(),
                    "pulumi".to_string(),
                    "cdktf".to_string(),
                ],
                file_patterns: vec![],
                content_patterns: vec![],
                process_names: vec![],
                condition: Some("file_access AND NOT excluded_process".to_string()),
            },
            alert: AlertConfig {
                channels: vec![AlertChannel::Stdout, AlertChannel::Desktop],
                message: Some("Suspicious access to AWS credentials by {process_name} (PID: {pid})".to_string()),
            },
            tags: vec!["credential".to_string(), "aws".to_string()],
            enabled: Some(true),
        },
        DetectionRule {
            id: "cred-access-ssh".to_string(),
            name: "SSH Key Access".to_string(),
            severity: Severity::High,
            description: "Non-standard process accessing SSH keys".to_string(),
            detection: Detection {
                file_paths: vec![
                    "~/.ssh/id_*".to_string(),
                    "~/.ssh/config".to_string(),
                    "~/.ssh/known_hosts".to_string(),
                ],
                excluded_processes: vec![
                    "ssh".to_string(),
                    "scp".to_string(),
                    "sftp".to_string(),
                    "ssh-agent".to_string(),
                    "git".to_string(),
                ],
                file_patterns: vec![],
                content_patterns: vec![],
                process_names: vec![],
                condition: None,
            },
            alert: AlertConfig {
                channels: vec![AlertChannel::Stdout, AlertChannel::Desktop],
                message: Some("Suspicious access to SSH keys by {process_name} (PID: {pid})".to_string()),
            },
            tags: vec!["credential".to_string(), "ssh".to_string()],
            enabled: Some(true),
        },
        DetectionRule {
            id: "cred-access-gpg".to_string(),
            name: "GPG Keyring Access".to_string(),
            severity: Severity::Medium,
            description: "Non-standard process accessing GPG keyring".to_string(),
            detection: Detection {
                file_paths: vec!["~/.gnupg/*".to_string()],
                excluded_processes: vec![
                    "gpg".to_string(),
                    "gpg2".to_string(),
                    "gpg-agent".to_string(),
                    "git".to_string(),
                ],
                file_patterns: vec![],
                content_patterns: vec![],
                process_names: vec![],
                condition: None,
            },
            alert: AlertConfig::default(),
            tags: vec!["credential".to_string(), "gpg".to_string()],
            enabled: Some(true),
        },
        DetectionRule {
            id: "cred-access-npm".to_string(),
            name: "NPM Token Access".to_string(),
            severity: Severity::High,
            description: "Non-standard process accessing npm credentials".to_string(),
            detection: Detection {
                file_paths: vec![
                    "~/.npmrc".to_string(),
                    "~/.config/npm/*".to_string(),
                ],
                excluded_processes: vec![
                    "npm".to_string(),
                    "npx".to_string(),
                    "pnpm".to_string(),
                    "yarn".to_string(),
                    "node".to_string(),
                ],
                file_patterns: vec![],
                content_patterns: vec![],
                process_names: vec![],
                condition: None,
            },
            alert: AlertConfig::default(),
            tags: vec!["credential".to_string(), "npm".to_string()],
            enabled: Some(true),
        },
        DetectionRule {
            id: "cred-access-docker".to_string(),
            name: "Docker Config Access".to_string(),
            severity: Severity::Medium,
            description: "Non-standard process accessing Docker credentials".to_string(),
            detection: Detection {
                file_paths: vec!["~/.docker/config.json".to_string()],
                excluded_processes: vec![
                    "docker".to_string(),
                    "dockerd".to_string(),
                    "containerd".to_string(),
                ],
                file_patterns: vec![],
                content_patterns: vec![],
                process_names: vec![],
                condition: None,
            },
            alert: AlertConfig::default(),
            tags: vec!["credential".to_string(), "docker".to_string()],
            enabled: Some(true),
        },
        DetectionRule {
            id: "cred-access-kube".to_string(),
            name: "Kubernetes Config Access".to_string(),
            severity: Severity::High,
            description: "Non-standard process accessing kubeconfig".to_string(),
            detection: Detection {
                file_paths: vec!["~/.kube/config".to_string()],
                excluded_processes: vec![
                    "kubectl".to_string(),
                    "helm".to_string(),
                    "k9s".to_string(),
                    "kubectx".to_string(),
                ],
                file_patterns: vec![],
                content_patterns: vec![],
                process_names: vec![],
                condition: None,
            },
            alert: AlertConfig::default(),
            tags: vec!["credential".to_string(), "kubernetes".to_string()],
            enabled: Some(true),
        },
        DetectionRule {
            id: "cred-access-gcloud".to_string(),
            name: "GCP Credential Access".to_string(),
            severity: Severity::High,
            description: "Non-standard process accessing GCP credentials".to_string(),
            detection: Detection {
                file_paths: vec!["~/.config/gcloud/*".to_string()],
                excluded_processes: vec![
                    "gcloud".to_string(),
                    "terraform".to_string(),
                    "pulumi".to_string(),
                ],
                file_patterns: vec![],
                content_patterns: vec![],
                process_names: vec![],
                condition: None,
            },
            alert: AlertConfig::default(),
            tags: vec!["credential".to_string(), "gcp".to_string()],
            enabled: Some(true),
        },
        DetectionRule {
            id: "cred-access-azure".to_string(),
            name: "Azure Credential Access".to_string(),
            severity: Severity::High,
            description: "Non-standard process accessing Azure credentials".to_string(),
            detection: Detection {
                file_paths: vec!["~/.azure/*".to_string()],
                excluded_processes: vec![
                    "az".to_string(),
                    "terraform".to_string(),
                    "pulumi".to_string(),
                ],
                file_patterns: vec![],
                content_patterns: vec![],
                process_names: vec![],
                condition: None,
            },
            alert: AlertConfig::default(),
            tags: vec!["credential".to_string(), "azure".to_string()],
            enabled: Some(true),
        },
    ]
}

pub fn supply_chain_rules() -> Vec<DetectionRule> {
    vec![
        DetectionRule {
            id: "supply-chain-node-modules".to_string(),
            name: "Node Modules Tampering".to_string(),
            severity: Severity::Critical,
            description: "Direct write to node_modules outside of package manager".to_string(),
            detection: Detection {
                file_paths: vec!["**/node_modules/**".to_string()],
                excluded_processes: vec![
                    "npm".to_string(),
                    "npx".to_string(),
                    "pnpm".to_string(),
                    "yarn".to_string(),
                    "node".to_string(),
                ],
                file_patterns: vec![],
                content_patterns: vec![],
                process_names: vec![],
                condition: None,
            },
            alert: AlertConfig {
                channels: vec![AlertChannel::Stdout, AlertChannel::Desktop],
                message: Some("node_modules tampered by {process_name} (PID: {pid}) — {path}".to_string()),
            },
            tags: vec!["supply-chain".to_string(), "node".to_string()],
            enabled: Some(true),
        },
        DetectionRule {
            id: "supply-chain-npmrc-write".to_string(),
            name: ".npmrc Modification".to_string(),
            severity: Severity::High,
            description: "Unexpected modification of .npmrc registry configuration".to_string(),
            detection: Detection {
                file_paths: vec![
                    "**/.npmrc".to_string(),
                    "~/.npmrc".to_string(),
                ],
                excluded_processes: vec![
                    "npm".to_string(),
                    "npx".to_string(),
                ],
                file_patterns: vec![],
                content_patterns: vec![],
                process_names: vec![],
                condition: None,
            },
            alert: AlertConfig::default(),
            tags: vec!["supply-chain".to_string(), "npm".to_string()],
            enabled: Some(true),
        },
        DetectionRule {
            id: "supply-chain-pip-conf".to_string(),
            name: "pip Configuration Modification".to_string(),
            severity: Severity::High,
            description: "Unexpected modification of pip configuration".to_string(),
            detection: Detection {
                file_paths: vec![
                    "~/.pip/pip.conf".to_string(),
                    "~/.config/pip/pip.conf".to_string(),
                ],
                excluded_processes: vec!["pip".to_string(), "pip3".to_string()],
                file_patterns: vec![],
                content_patterns: vec![],
                process_names: vec![],
                condition: None,
            },
            alert: AlertConfig::default(),
            tags: vec!["supply-chain".to_string(), "python".to_string()],
            enabled: Some(true),
        },
    ]
}

pub fn exfiltration_rules() -> Vec<DetectionRule> {
    vec![
        DetectionRule {
            id: "exfil-curl-unknown".to_string(),
            name: "Curl to External Host".to_string(),
            severity: Severity::Medium,
            description: "curl/wget making outbound request during build or install".to_string(),
            detection: Detection {
                file_paths: vec![],
                excluded_processes: vec![],
                file_patterns: vec![],
                content_patterns: vec![],
                process_names: vec!["curl".to_string(), "wget".to_string()],
                condition: Some("process_spawn AND process_name IN names".to_string()),
            },
            alert: AlertConfig::default(),
            tags: vec!["exfiltration".to_string(), "network".to_string()],
            enabled: Some(true),
        },
    ]
}

pub fn all_builtin_rules() -> Vec<DetectionRule> {
    let mut rules = Vec::new();
    rules.extend(credential_access_rules());
    rules.extend(supply_chain_rules());
    rules.extend(exfiltration_rules());
    rules
}
