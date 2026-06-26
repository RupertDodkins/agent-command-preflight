use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sandbox {
    pub workspace: String,
    #[serde(default)]
    pub network: bool,
    #[serde(default)]
    pub write_roots: Vec<String>,
    #[serde(default)]
    pub trusted_domains: Vec<String>,
    #[serde(default = "default_approval_policy")]
    pub approval_policy: String,
    #[serde(default)]
    pub allow_package_installs: bool,
}

fn default_approval_policy() -> String {
    "on-request".to_string()
}

impl Default for Sandbox {
    fn default() -> Self {
        Self {
            workspace: "/repo".to_string(),
            network: false,
            write_roots: vec!["/repo".to_string()],
            trusted_domains: vec![],
            approval_policy: "on-request".to_string(),
            allow_package_installs: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Risk {
    Low,
    Medium,
    High,
    Critical,
}

impl Default for Risk {
    fn default() -> Self {
        Risk::Low
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    AllowInSandbox,
    Ask,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum EffectKind {
    ReadFile,
    WriteFile,
    DeletePath,
    ExecuteLocal,
    ExecuteProjectCode,
    ExecuteDownloadedCode,
    NetworkRead,
    NetworkWrite,
    SecretRead,
    SecretExfiltration,
    WorkspaceEscape,
    PackageInstall,
    GitRemoteMutation,
    InfraMutation,
    DatabaseMutation,
    PrivilegedHostAction,
    ObfuscatedExecution,
    CommandSubstitution,
    Pipeline,
    UnknownExecution,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Span {
    pub start: usize,
    pub end: usize,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Effect {
    pub kind: EffectKind,
    pub risk: Risk,
    pub evidence: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    pub span: Span,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandNode {
    pub executable: String,
    pub args: Vec<String>,
    pub span: Span,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedirectNode {
    pub op: String,
    pub target: Option<String>,
    pub span: Span,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineNode {
    pub stages: Vec<String>,
    pub span: Span,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainNode {
    pub op: String,
    pub span: Span,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubstitutionNode {
    pub kind: String,
    pub text: String,
    pub span: Span,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvAssignment {
    pub name: String,
    pub value: String,
    pub span: Span,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Flow {
    pub from_effect: EffectKind,
    pub to_effect: EffectKind,
    pub evidence: String,
    pub risk: Risk,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Analysis {
    pub command: String,
    pub sandbox: Sandbox,
    pub ast_root: String,
    pub commands: Vec<CommandNode>,
    pub redirects: Vec<RedirectNode>,
    pub pipelines: Vec<PipelineNode>,
    pub chains: Vec<ChainNode>,
    pub substitutions: Vec<SubstitutionNode>,
    pub env_assignments: Vec<EnvAssignment>,
    pub unsupported_constructs: Vec<String>,
    pub effects: Vec<Effect>,
    pub flows: Vec<Flow>,
    pub parse_errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEvidence {
    pub rule: String,
    pub effect: EffectKind,
    pub evidence: String,
    pub decision: Decision,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Review {
    pub decision: Decision,
    pub risk: Risk,
    pub reason: String,
    pub policy_evidence: Vec<PolicyEvidence>,
    pub analysis: Analysis,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub safer_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalCase {
    pub id: String,
    pub command: String,
    #[serde(alias = "expected_decision")]
    pub expected: Decision,
    pub category: String,
    #[serde(default)]
    pub severity: Risk,
    #[serde(default)]
    pub sandbox: Option<Sandbox>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalFailure {
    pub id: String,
    pub command: String,
    pub expected: Decision,
    pub actual: Decision,
    pub category: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalReport {
    pub total: usize,
    pub pass: usize,
    pub fail: usize,
    pub pass_rate: f64,
    pub high_risk_false_allows: usize,
    pub secret_exfiltration_false_allows: usize,
    pub destructive_or_infra_false_allows: usize,
    pub over_conservative: usize,
    pub by_category: Vec<CategoryReport>,
    pub failures: Vec<EvalFailure>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParserSmokeCase {
    pub id: String,
    pub command: String,
    pub expected_features: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParserSmokeResult {
    pub total: usize,
    pub pass: usize,
    pub fail: usize,
    pub failures: Vec<ParserSmokeFailure>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParserSmokeFailure {
    pub id: String,
    pub command: String,
    pub missing_features: Vec<String>,
    pub observed_features: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryReport {
    pub category: String,
    pub pass: usize,
    pub total: usize,
}
