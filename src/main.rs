mod analyzer;
mod model;
mod policy;

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use model::{
    Analysis, CategoryReport, Decision, EffectKind, EvalCase, EvalFailure, EvalReport,
    ParserSmokeCase, ParserSmokeFailure, ParserSmokeResult, Risk, Sandbox,
};

#[derive(Parser)]
#[command(name = "agent-command-preflight")]
#[command(about = "Static preflight evidence engine for coding-agent shell commands")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Analyze {
        command: Vec<String>,
        #[arg(long)]
        sandbox: Option<PathBuf>,
    },
    Effects {
        command: Vec<String>,
        #[arg(long)]
        sandbox: Option<PathBuf>,
    },
    Decide {
        command: Vec<String>,
        #[arg(long)]
        sandbox: Option<PathBuf>,
    },
    Eval {
        #[arg(long, default_value = "cases/agent-command-safety.jsonl")]
        suite: PathBuf,
    },
    Smoke {
        #[arg(long, default_value = "cases/parser-smoke.jsonl")]
        suite: PathBuf,
    },
    Report {
        command: Vec<String>,
        #[arg(long, default_value = "html")]
        format: String,
        #[arg(long)]
        sandbox: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Analyze { command, sandbox } => {
            let analysis = analyze_from_args(command, sandbox)?;
            print_json(&analysis)?;
        }
        Command::Effects { command, sandbox } => {
            let analysis = analyze_from_args(command, sandbox)?;
            print_json(&analysis.effects)?;
        }
        Command::Decide { command, sandbox } => {
            let analysis = analyze_from_args(command, sandbox)?;
            let review = policy::review(analysis);
            print_json(&review)?;
        }
        Command::Eval { suite } => {
            let report = run_eval(&suite)?;
            print_json(&report)?;
            if report.fail > 0 || report.high_risk_false_allows > 0 {
                std::process::exit(1);
            }
        }
        Command::Smoke { suite } => {
            let report = run_smoke(&suite)?;
            print_json(&report)?;
            if report.pass < 18 || report.fail > 2 {
                std::process::exit(1);
            }
        }
        Command::Report {
            command,
            format,
            sandbox,
        } => {
            let analysis = analyze_from_args(command, sandbox)?;
            let review = policy::review(analysis);
            match format.as_str() {
                "json" => print_json(&review)?,
                "md" | "markdown" => println!("{}", render_markdown(&review)),
                "html" => println!("{}", render_html(&review)),
                other => anyhow::bail!("unsupported report format: {other}"),
            }
        }
    }
    Ok(())
}

fn analyze_from_args(command: Vec<String>, sandbox_path: Option<PathBuf>) -> Result<Analysis> {
    let command = if command.is_empty() {
        let mut input = String::new();
        io::stdin().read_to_string(&mut input)?;
        input.trim().to_string()
    } else {
        command.join(" ")
    };
    let sandbox = load_sandbox(sandbox_path)?;
    analyzer::analyze(&command, sandbox)
}

fn load_sandbox(path: Option<PathBuf>) -> Result<Sandbox> {
    match path {
        Some(path) => {
            let text = fs::read_to_string(&path)
                .with_context(|| format!("reading sandbox {}", path.display()))?;
            Ok(serde_json::from_str(&text)
                .with_context(|| format!("parsing sandbox {}", path.display()))?)
        }
        None => Ok(Sandbox::default()),
    }
}

fn print_json<T: serde::Serialize>(value: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn read_jsonl<T: serde::de::DeserializeOwned>(path: &PathBuf) -> Result<Vec<T>> {
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut out = Vec::new();
    for (idx, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        out.push(
            serde_json::from_str(trimmed)
                .with_context(|| format!("{}:{}", path.display(), idx + 1))?,
        );
    }
    Ok(out)
}

fn run_eval(path: &PathBuf) -> Result<EvalReport> {
    let cases: Vec<EvalCase> = read_jsonl(path)?;
    let mut pass = 0;
    let mut failures = Vec::new();
    let mut by_category: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    let mut high_risk_false_allows = 0;
    let mut secret_exfiltration_false_allows = 0;
    let mut destructive_or_infra_false_allows = 0;
    let mut over_conservative = 0;

    for case in &cases {
        let sandbox = case.sandbox.clone().unwrap_or_default();
        let analysis = analyzer::analyze(&case.command, sandbox)?;
        let review = policy::review(analysis);
        let actual = review.decision;
        let ok = actual == case.expected;
        let entry = by_category.entry(case.category.clone()).or_insert((0, 0));
        entry.1 += 1;
        if ok {
            pass += 1;
            entry.0 += 1;
        } else {
            failures.push(EvalFailure {
                id: case.id.clone(),
                command: case.command.clone(),
                expected: case.expected.clone(),
                actual: actual.clone(),
                category: case.category.clone(),
            });
        }

        let severity = effective_severity(case);
        if is_false_allow(&actual, &case.expected) && severity >= Risk::High {
            high_risk_false_allows += 1;
        }
        if is_false_allow(&actual, &case.expected) && case.category.contains("secret") {
            secret_exfiltration_false_allows += 1;
        }
        if is_false_allow(&actual, &case.expected)
            && (case.category.contains("workspace")
                || case.category.contains("home_dotfile")
                || case.category.contains("destructive")
                || case.category.contains("infra")
                || case.category.contains("cloud")
                || case.category.contains("git_remote"))
        {
            destructive_or_infra_false_allows += 1;
        }
        if more_restrictive(&actual, &case.expected) {
            over_conservative += 1;
        }
    }

    let total = cases.len();
    Ok(EvalReport {
        total,
        pass,
        fail: total.saturating_sub(pass),
        pass_rate: if total == 0 {
            0.0
        } else {
            pass as f64 / total as f64
        },
        high_risk_false_allows,
        secret_exfiltration_false_allows,
        destructive_or_infra_false_allows,
        over_conservative,
        by_category: by_category
            .into_iter()
            .map(|(category, (pass, total))| CategoryReport {
                category,
                pass,
                total,
            })
            .collect(),
        failures,
    })
}

fn run_smoke(path: &PathBuf) -> Result<ParserSmokeResult> {
    let cases: Vec<ParserSmokeCase> = read_jsonl(path)?;
    let mut pass = 0;
    let mut failures = Vec::new();

    for case in &cases {
        let analysis = analyzer::analyze(&case.command, Sandbox::default())?;
        let observed = observed_features(&analysis);
        let missing = case
            .expected_features
            .iter()
            .filter(|feature| !observed.contains(*feature))
            .cloned()
            .collect::<Vec<_>>();
        if missing.is_empty() {
            pass += 1;
        } else {
            failures.push(ParserSmokeFailure {
                id: case.id.clone(),
                command: case.command.clone(),
                missing_features: missing,
                observed_features: observed,
            });
        }
    }

    Ok(ParserSmokeResult {
        total: cases.len(),
        pass,
        fail: cases.len().saturating_sub(pass),
        failures,
    })
}

fn observed_features(analysis: &Analysis) -> Vec<String> {
    let mut features = Vec::new();
    let lower = analysis.command.to_ascii_lowercase();
    if !analysis.commands.is_empty() {
        features.push("commands".to_string());
        features.push("simple_command".to_string());
        features.push("argv".to_string());
    }
    if analysis.commands.len() > 1 {
        features.push("simple_commands".to_string());
    }
    if !analysis.redirects.is_empty() {
        features.push("redirection".to_string());
        if analysis.redirects.iter().any(|r| r.op.contains('>')) {
            features.push("stdout_redirection".to_string());
        }
        if analysis.redirects.iter().any(|r| {
            r.target
                .as_deref()
                .map(|t| t.starts_with("~/") || t.starts_with("$HOME"))
                .unwrap_or(false)
        }) {
            features.push("home_path_target".to_string());
        }
    }
    if !analysis.pipelines.is_empty() {
        features.push("pipeline".to_string());
        features.push("stdin_flow".to_string());
    }
    if !analysis.chains.is_empty() {
        features.push("chain".to_string());
        if analysis.chains.iter().any(|c| c.op == "&&") {
            features.push("and_chain".to_string());
        }
        if analysis.chains.iter().any(|c| c.op == "||") {
            features.push("or_chain".to_string());
        }
    }
    if !analysis.substitutions.is_empty() {
        features.push("substitution".to_string());
        if analysis
            .substitutions
            .iter()
            .any(|s| s.kind == "process_substitution")
        {
            features.push("process_substitution".to_string());
        }
        if analysis
            .substitutions
            .iter()
            .any(|s| s.kind == "command_substitution")
        {
            features.push("command_substitution".to_string());
        }
        if analysis.commands.len() > 1 {
            features.push("nested_command".to_string());
            features.push("nested_commands".to_string());
        }
    }
    if !analysis.env_assignments.is_empty() {
        features.push("env_assignment".to_string());
        features.push("env_assignments".to_string());
    }
    if !analysis.unsupported_constructs.is_empty() || !analysis.parse_errors.is_empty() {
        features.push("unsupported".to_string());
        if lower.starts_with("if ") || lower.contains("; then ") {
            features.push("if_statement".to_string());
        }
        if lower.starts_with("for ") {
            features.push("for_loop".to_string());
        }
    }
    for command in &analysis.commands {
        features.push(format!("command:{}", command.executable));
        if command.args.iter().any(|arg| {
            !arg.starts_with('-')
                && !arg.contains("://")
                && (arg.contains('/')
                    || arg.contains('.')
                    || arg
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'))
        }) {
            features.push("relative_path_arg".to_string());
            features.push("relative_path_args".to_string());
        }
        if command.args.iter().any(|arg| arg == "--") {
            features.push("double_dash_passthrough".to_string());
        }
        if command.args.iter().any(|arg| {
            matches!(arg.as_str(), "-exec" | "--pre") || arg.starts_with("--checkpoint-action=exec")
        }) {
            features.push("wrapper_exec_flag".to_string());
        }
        if command.executable == "bash" || command.executable == "sh" {
            features.push("interpreter_sink".to_string());
        }
        if matches!(
            command.executable.as_str(),
            "kubectl" | "docker" | "aws" | "gcloud" | "az"
        ) {
            features.push("infra_cli".to_string());
        }
    }
    for effect in &analysis.effects {
        match effect.kind {
            EffectKind::Pipeline => features.push("pipeline".to_string()),
            EffectKind::CommandSubstitution => features.push("substitution".to_string()),
            EffectKind::WorkspaceEscape => features.push("workspace_escape".to_string()),
            EffectKind::NetworkRead | EffectKind::NetworkWrite => {
                features.push("network".to_string())
            }
            EffectKind::SecretRead => features.push("secret".to_string()),
            EffectKind::WriteFile => {
                features.push("write".to_string());
                features.push("workspace_relative_write".to_string());
                features.push("file_write_arg".to_string());
            }
            EffectKind::ExecuteDownloadedCode => features.push("downloaded_exec".to_string()),
            EffectKind::ObfuscatedExecution => features.push("dynamic_shell".to_string()),
            EffectKind::GitRemoteMutation => features.push("git_mutation".to_string()),
            EffectKind::InfraMutation => features.push("infra".to_string()),
            EffectKind::DatabaseMutation => features.push("database".to_string()),
            EffectKind::ExecuteProjectCode => features.push("project_code".to_string()),
            _ => {}
        }
    }
    if lower.contains('"') || lower.contains('\'') {
        features.push("quoted_arg".to_string());
    }
    if lower.contains("$(") && lower.contains('"') {
        features.push("quoted_substitution".to_string());
    }
    if lower.contains("http://") || lower.contains("https://") {
        features.push("network_url_arg".to_string());
    }
    if lower.contains(".env")
        || lower.contains(".ssh")
        || lower.contains("token")
        || lower.contains("api_key")
    {
        features.push("secret_path_arg".to_string());
    }
    if lower.contains("bash -c") || lower.contains("sh -c") {
        features.push("nested_shell_string".to_string());
    }
    if lower.contains(" | ") && (lower.contains('"') || lower.contains('\'')) {
        features.push("pipeline_in_quoted_arg".to_string());
    }
    if lower.contains(".env")
        && lower.contains("curl")
        && (lower.contains('"') || lower.contains('\''))
    {
        features.push("secret_to_network_in_quoted_arg".to_string());
    }
    if lower.contains("\\;") {
        features.push("escaped_semicolon".to_string());
    }
    if lower.contains("tar -cf") || lower.contains("tar -czf") {
        features.push("archive_write_arg".to_string());
    }
    if lower.contains("cargo test") {
        features.push("test_command".to_string());
    }
    if lower.contains(" then ") || lower.contains("; then ") {
        features.push("then_command".to_string());
    }
    if lower.starts_with('(') {
        features.push("subshell".to_string());
    }
    if lower.contains("cd ") {
        features.push("working_directory_change".to_string());
    }
    if lower.contains('*') {
        features.push("glob_arg".to_string());
    }
    if lower.contains('$') {
        features.push("variable_expansion".to_string());
    }
    if lower.contains("\"$") {
        features.push("quoted_variable".to_string());
    }
    if lower.contains("python -c") || lower.contains("python3 -c") {
        features.push("interpreter_inline_code".to_string());
    }
    if lower.contains("git -c") {
        features.push("inline_config".to_string());
    }
    if lower.contains("alias.") {
        features.push("alias_definition".to_string());
        features.push("indirect_subcommand".to_string());
    }
    if lower.contains("kubectl set")
        || lower.contains("kubectl delete")
        || lower.contains("kubectl apply")
    {
        features.push("mutation_subcommand".to_string());
        features.push("resource_arg".to_string());
    }
    if lower.contains("docker run") {
        features.push("container_run".to_string());
    }
    if lower.contains(" -v ") || lower.contains("--volume") {
        features.push("volume_mount".to_string());
    }
    if lower.contains("install.sh") && lower.contains("bash") {
        features.push("interpreter_file_arg".to_string());
    }
    features.sort();
    features.dedup();
    features
}

fn is_false_allow(actual: &Decision, expected: &Decision) -> bool {
    rank(actual) < rank(expected)
}

fn more_restrictive(actual: &Decision, expected: &Decision) -> bool {
    rank(actual) > rank(expected)
}

fn rank(decision: &Decision) -> u8 {
    match decision {
        Decision::Allow => 0,
        Decision::AllowInSandbox => 1,
        Decision::Ask => 2,
        Decision::Deny => 3,
    }
}

fn effective_severity(case: &EvalCase) -> Risk {
    if case.severity != Risk::Low {
        return case.severity.clone();
    }
    if matches!(case.expected, Decision::Deny) {
        Risk::High
    } else if case.category.contains("secret")
        || case.category.contains("home")
        || case.category.contains("workspace")
        || case.category.contains("infra")
        || case.category.contains("cloud")
        || case.category.contains("database")
        || case.category.contains("git")
        || case.category.contains("destructive")
    {
        Risk::High
    } else if matches!(case.expected, Decision::Ask | Decision::AllowInSandbox) {
        Risk::Medium
    } else {
        Risk::Low
    }
}

fn render_markdown(review: &model::Review) -> String {
    let mut out = String::new();
    out.push_str(&format!("# Command Preflight Report\n\n"));
    out.push_str(&format!("```bash\n{}\n```\n\n", review.analysis.command));
    out.push_str(&format!("**Decision:** `{:?}`  \n", review.decision));
    out.push_str(&format!("**Risk:** `{:?}`  \n", review.risk));
    out.push_str(&format!("**Reason:** {}\n\n", review.reason));
    if let Some(path) = &review.safer_path {
        out.push_str(&format!("**Safer path:** {}\n\n", path));
    }

    out.push_str("## Parsed Commands\n\n");
    for command in &review.analysis.commands {
        out.push_str(&format!(
            "- `{}` args: `{:?}` span: `{}`\n",
            command.executable, command.args, command.span.text
        ));
    }

    out.push_str("\n## Normalized Shell Structure\n\n");
    if review.analysis.env_assignments.is_empty()
        && review.analysis.redirects.is_empty()
        && review.analysis.pipelines.is_empty()
        && review.analysis.chains.is_empty()
        && review.analysis.substitutions.is_empty()
        && review.analysis.unsupported_constructs.is_empty()
    {
        out.push_str("- no redirections, pipelines, substitutions, env assignments, or unsupported constructs detected\n");
    } else {
        for assignment in &review.analysis.env_assignments {
            out.push_str(&format!(
                "- env assignment `{}`=`{}` span=`{}`\n",
                assignment.name, assignment.value, assignment.span.text
            ));
        }
        for redirect in &review.analysis.redirects {
            out.push_str(&format!(
                "- redirect op=`{}` target=`{:?}` span=`{}`\n",
                redirect.op, redirect.target, redirect.span.text
            ));
        }
        for pipeline in &review.analysis.pipelines {
            out.push_str(&format!(
                "- pipeline stages=`{:?}` span=`{}`\n",
                pipeline.stages, pipeline.span.text
            ));
        }
        for chain in &review.analysis.chains {
            out.push_str(&format!(
                "- chain op=`{}` span=`{}`\n",
                chain.op, chain.span.text
            ));
        }
        for substitution in &review.analysis.substitutions {
            out.push_str(&format!(
                "- substitution kind=`{}` text=`{}`\n",
                substitution.kind, substitution.text
            ));
        }
        for unsupported in &review.analysis.unsupported_constructs {
            out.push_str(&format!("- unsupported `{}`\n", unsupported));
        }
    }

    out.push_str("\n## Effects\n\n");
    for effect in &review.analysis.effects {
        out.push_str(&format!(
            "- `{:?}` risk=`{:?}` evidence={} span=`{}`",
            effect.kind, effect.risk, effect.evidence, effect.span.text
        ));
        if let Some(path) = &effect.path {
            out.push_str(&format!(" path=`{}`", path));
        }
        if let Some(target) = &effect.target {
            out.push_str(&format!(" target=`{}`", target));
        }
        out.push('\n');
    }

    out.push_str("\n## Flows\n\n");
    if review.analysis.flows.is_empty() {
        out.push_str("- none inferred\n");
    } else {
        for flow in &review.analysis.flows {
            out.push_str(&format!(
                "- `{:?}` -> `{:?}` risk=`{:?}` evidence={}\n",
                flow.from_effect, flow.to_effect, flow.risk, flow.evidence
            ));
        }
    }

    out.push_str("\n## Policy Evidence\n\n");
    for evidence in &review.policy_evidence {
        out.push_str(&format!(
            "- rule=`{}` decision=`{:?}` effect=`{:?}` evidence={}\n",
            evidence.rule, evidence.decision, evidence.effect, evidence.evidence
        ));
    }

    if !review.analysis.parse_errors.is_empty() {
        out.push_str("\n## Parse Warnings\n\n");
        for err in &review.analysis.parse_errors {
            out.push_str(&format!("- {}\n", err));
        }
    }

    out
}

fn render_html(review: &model::Review) -> String {
    let md = render_markdown(review);
    let escaped = html_escape(&md);
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Command Preflight Report</title><style>body{{font-family:ui-sans-serif,system-ui;margin:32px;line-height:1.45;max-width:1120px}}pre{{background:#111;color:#eee;padding:14px;border-radius:8px;overflow:auto}}code{{background:#eee;padding:2px 4px;border-radius:4px}}h1,h2{{line-height:1.1}} </style></head><body><pre>{escaped}</pre></body></html>"
    )
}

fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_jsonl(contents: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "agent-command-preflight-test-{}-{nanos}.jsonl",
            std::process::id()
        ));
        fs::write(&path, contents).expect("write temp jsonl");
        path
    }

    #[test]
    fn read_jsonl_skips_blank_lines_and_comments() {
        let path = temp_jsonl(
            r#"
# ignored
{"id":"one","command":"pwd","expected_decision":"allow","category":"benign"}

{"id":"two","command":"git status --short","expected_decision":"allow","category":"benign"}
"#,
        );

        let cases: Vec<EvalCase> = read_jsonl(&path).expect("jsonl should parse");
        fs::remove_file(path).ok();

        assert_eq!(cases.len(), 2);
        assert_eq!(cases[0].id, "one");
        assert_eq!(cases[1].id, "two");
    }

    #[test]
    fn eval_report_counts_false_allows_and_over_conservative_decisions() {
        let path = temp_jsonl(
            r#"
{"id":"false-allow","command":"pwd","expected_decision":"deny","category":"destructive_filesystem"}
{"id":"over-conservative","command":"cat .env","expected_decision":"allow","category":"benign_read_only"}
"#,
        );

        let report = run_eval(&path).expect("eval should run");
        fs::remove_file(path).ok();

        assert_eq!(report.total, 2);
        assert_eq!(report.pass, 0);
        assert_eq!(report.fail, 2);
        assert_eq!(report.high_risk_false_allows, 1);
        assert_eq!(report.destructive_or_infra_false_allows, 1);
        assert_eq!(report.over_conservative, 1);
    }

    #[test]
    fn render_html_escapes_markdown_report_body() {
        let analysis = analyzer::analyze("printf '<tag>' > reports/out.html", Sandbox::default())
            .expect("analysis should succeed");
        let review = policy::review(analysis);
        let html = render_html(&review);

        assert!(html.contains("&lt;tag&gt;"));
        assert!(!html.contains("```bash\nprintf '<tag>'"));
    }
}
