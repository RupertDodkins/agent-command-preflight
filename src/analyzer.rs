use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

use anyhow::{anyhow, Result};
use tree_sitter::{Node, Parser};

use crate::model::{
    Analysis, ChainNode, CommandNode, Effect, EffectKind, EnvAssignment, Flow, PipelineNode,
    RedirectNode, Risk, Sandbox, Span, SubstitutionNode,
};

pub fn analyze(command: &str, sandbox: Sandbox) -> Result<Analysis> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_bash::LANGUAGE.into())
        .map_err(|e| anyhow!("failed to load bash grammar: {e}"))?;
    let tree = parser
        .parse(command, None)
        .ok_or_else(|| anyhow!("tree-sitter failed to parse command"))?;
    let root = tree.root_node();

    let mut parse_errors = Vec::new();
    collect_parse_errors(root, command, &mut parse_errors);

    let mut commands = Vec::new();
    collect_command_nodes(root, command, &mut commands);
    dedupe_commands(&mut commands);
    if commands.is_empty() && !command.trim().is_empty() {
        commands.push(command_node_from_text(command, 0));
    }

    let mut redirects = Vec::new();
    let mut pipelines = Vec::new();
    let mut substitutions = Vec::new();
    let mut env_assignments = Vec::new();
    let mut unsupported_constructs = Vec::new();
    collect_normalized_nodes(
        root,
        command,
        &mut redirects,
        &mut pipelines,
        &mut substitutions,
        &mut env_assignments,
        &mut unsupported_constructs,
    );
    redirects.extend(redirect_targets(command).into_iter().map(|(op, target)| {
        RedirectNode {
            op: command[op.0..op.1]
                .chars()
                .take_while(|c| *c == '>' || *c == '<')
                .collect(),
            target: Some(target),
            span: Span {
                start: op.0,
                end: op.1,
                text: command[op.0..op.1].to_string(),
            },
        }
    }));
    dedupe_redirects(&mut redirects);
    let chains = collect_chain_nodes(command);

    let mut effects = Vec::new();
    collect_structural_effects(root, command, &mut effects);
    collect_command_effects(&commands, command, &sandbox, &mut effects);
    collect_redirect_effects(command, &sandbox, &mut effects);
    dedupe_effects(&mut effects);

    let flows = infer_flows(&effects, command);

    Ok(Analysis {
        command: command.to_string(),
        sandbox,
        ast_root: root.kind().to_string(),
        commands,
        redirects,
        pipelines,
        chains,
        substitutions,
        env_assignments,
        unsupported_constructs,
        effects,
        flows,
        parse_errors,
    })
}

fn collect_parse_errors(node: Node, source: &str, errors: &mut Vec<String>) {
    if node.is_error() || node.is_missing() {
        errors.push(format!(
            "{} at {}",
            node.kind(),
            span_for(node, source).text
        ));
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_parse_errors(child, source, errors);
    }
}

fn collect_command_nodes(node: Node, source: &str, out: &mut Vec<CommandNode>) {
    let kind = node.kind();
    if kind == "command" || kind == "simple_command" {
        let text = node_text(node, source);
        if let Some(cmd) = parse_command_text(&text, node.start_byte()) {
            out.push(cmd);
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_command_nodes(child, source, out);
    }
}

fn collect_normalized_nodes(
    node: Node,
    source: &str,
    redirects: &mut Vec<RedirectNode>,
    pipelines: &mut Vec<PipelineNode>,
    substitutions: &mut Vec<SubstitutionNode>,
    env_assignments: &mut Vec<EnvAssignment>,
    unsupported_constructs: &mut Vec<String>,
) {
    let kind = node.kind();
    match kind {
        "file_redirect" | "heredoc_redirect" => {
            redirects.push(redirect_node_from_ast(node, source))
        }
        "pipeline" => pipelines.push(PipelineNode {
            stages: pipeline_stages(node, source),
            span: span_for(node, source),
        }),
        "command_substitution" | "process_substitution" => substitutions.push(SubstitutionNode {
            kind: kind.to_string(),
            text: node_text(node, source),
            span: span_for(node, source),
        }),
        "variable_assignment" => env_assignments.push(env_assignment_from_ast(node, source)),
        "heredoc_body"
        | "case_statement"
        | "for_statement"
        | "while_statement"
        | "if_statement"
        | "function_definition" => {
            unsupported_constructs.push(format!("{}: {}", kind, node_text(node, source)))
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_normalized_nodes(
            child,
            source,
            redirects,
            pipelines,
            substitutions,
            env_assignments,
            unsupported_constructs,
        );
    }
}

fn collect_structural_effects(node: Node, source: &str, out: &mut Vec<Effect>) {
    let kind = node.kind();
    match kind {
        "pipeline" => out.push(effect(
            EffectKind::Pipeline,
            Risk::Medium,
            "pipeline connects one command's output to another command's input",
            span_for(node, source),
        )),
        "command_substitution" => out.push(effect(
            EffectKind::CommandSubstitution,
            Risk::High,
            "command substitution executes nested shell code before the outer command",
            span_for(node, source),
        )),
        "process_substitution" => out.push(effect(
            EffectKind::CommandSubstitution,
            Risk::High,
            "process substitution executes nested shell code as a file-like argument",
            span_for(node, source),
        )),
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_structural_effects(child, source, out);
    }
}

fn redirect_node_from_ast(node: Node, source: &str) -> RedirectNode {
    let text = node_text(node, source);
    let op = if text.contains(">>") {
        ">>"
    } else if text.contains('>') {
        ">"
    } else if text.contains("<<") {
        "<<"
    } else if text.contains('<') {
        "<"
    } else {
        "redirect"
    };
    RedirectNode {
        op: op.to_string(),
        target: redirect_target_from_text(&text),
        span: span_for(node, source),
    }
}

fn redirect_target_from_text(text: &str) -> Option<String> {
    let mut seen_op = false;
    for word in shell_words(text) {
        if seen_op && !word.chars().all(|c| c == '>' || c == '<') {
            return Some(word);
        }
        if word.contains('>') || word.contains('<') {
            seen_op = true;
        }
    }
    None
}

fn pipeline_stages(node: Node, source: &str) -> Vec<String> {
    let mut stages = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "command"
            || child.kind() == "simple_command"
            || child.kind() == "redirected_statement"
        {
            stages.push(node_text(child, source));
        }
    }
    if stages.is_empty() {
        stages = node_text(node, source)
            .split('|')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
    }
    stages
}

fn env_assignment_from_ast(node: Node, source: &str) -> EnvAssignment {
    let text = node_text(node, source);
    let (name, value) = text.split_once('=').unwrap_or((&text, ""));
    EnvAssignment {
        name: name.to_string(),
        value: value.to_string(),
        span: span_for(node, source),
    }
}

fn collect_chain_nodes(command: &str) -> Vec<ChainNode> {
    let mut out = Vec::new();
    let bytes = command.as_bytes();
    let mut i = 0;
    let mut quote: Option<u8> = None;
    while i < bytes.len() {
        let b = bytes[i];
        if let Some(q) = quote {
            if b == q {
                quote = None;
            }
            i += 1;
            continue;
        }
        if b == b'\'' || b == b'"' {
            quote = Some(b);
            i += 1;
            continue;
        }
        let op = if i + 1 < bytes.len() && &command[i..i + 2] == "&&" {
            Some("&&")
        } else if i + 1 < bytes.len() && &command[i..i + 2] == "||" {
            Some("||")
        } else if b == b';' {
            Some(";")
        } else {
            None
        };
        if let Some(op) = op {
            out.push(ChainNode {
                op: op.to_string(),
                span: Span {
                    start: i,
                    end: i + op.len(),
                    text: op.to_string(),
                },
            });
            i += op.len();
        } else {
            i += 1;
        }
    }
    out
}

fn collect_command_effects(
    commands: &[CommandNode],
    full_command: &str,
    sandbox: &Sandbox,
    out: &mut Vec<Effect>,
) {
    for cmd in commands {
        let exe = strip_wrappers(&cmd.executable);
        let args = cmd.args.join(" ");
        let text = cmd.span.text.to_ascii_lowercase();

        if ["curl", "wget", "http", "https"].contains(&exe.as_str())
            || contains_url(&cmd.span.text)
            || exe == "scp"
            || exe == "nc"
            || exe == "netcat"
        {
            let url = extract_url(&cmd.span.text);
            let mut e = effect(
                if looks_like_network_write(&cmd.span.text)
                    || exe == "scp"
                    || exe == "nc"
                    || exe == "netcat"
                {
                    EffectKind::NetworkWrite
                } else {
                    EffectKind::NetworkRead
                },
                if exe == "scp" || exe == "nc" || exe == "netcat" {
                    Risk::Critical
                } else if sandbox.network {
                    Risk::Medium
                } else {
                    Risk::High
                },
                "command crosses the network boundary",
                cmd.span.clone(),
            );
            e.target = url;
            out.push(e);
            if let Some(path) = network_output_path(&exe, &cmd.args) {
                let outside = !path_inside_write_roots(&path, sandbox);
                let mut write = effect(
                    if outside {
                        EffectKind::WorkspaceEscape
                    } else {
                        EffectKind::WriteFile
                    },
                    if outside { Risk::High } else { Risk::Medium },
                    "network command writes downloaded content to a local path",
                    cmd.span.clone(),
                );
                write.path = Some(path);
                out.push(write);
            }
        }

        if is_package_manager_install(&exe, &args) {
            out.push(effect(
                EffectKind::PackageInstall,
                if sandbox.allow_package_installs {
                    Risk::Medium
                } else {
                    Risk::High
                },
                "package installation mutates dependencies and may execute install scripts",
                cmd.span.clone(),
            ));
        }

        if is_package_registry_mutation(&exe, &cmd.args) {
            out.push(effect(
                EffectKind::NetworkWrite,
                Risk::Critical,
                "command publishes, yanks, versions, or mutates package registry metadata",
                cmd.span.clone(),
            ));
        }

        if is_package_metadata_network(&exe, &cmd.args) {
            out.push(effect(
                EffectKind::NetworkRead,
                if sandbox.network {
                    Risk::Medium
                } else {
                    Risk::High
                },
                "package metadata command reaches a package registry",
                cmd.span.clone(),
            ));
        }

        if is_secret_read_command(&exe, &cmd.args) || mentions_secret(&cmd.span.text) {
            let mut e = effect(
                EffectKind::SecretRead,
                if credential_probe(&cmd.span.text) {
                    Risk::Critical
                } else {
                    Risk::High
                },
                "command reads secret-like material",
                cmd.span.clone(),
            );
            e.path = first_secret_path(&cmd.span.text);
            out.push(e);
        }

        if exe == "env" || exe == "printenv" {
            out.push(effect(
                EffectKind::SecretRead,
                Risk::High,
                "environment dump may include secret-like material",
                cmd.span.clone(),
            ));
        }

        if secret_copy_outside(&exe, &cmd.args, sandbox) || secret_exfiltration_text(&text) {
            out.push(effect(
                EffectKind::SecretExfiltration,
                Risk::Critical,
                "secret-like material is copied outside the workspace or can flow to an external sink",
                cmd.span.clone(),
            ));
        }

        if is_delete_command(&exe, &cmd.args)
            || dangerous_delete_text(&text)
            || destructive_file_utility(&exe, &cmd.args)
        {
            let path = cmd.args.iter().find(|arg| !arg.starts_with('-')).cloned();
            let mut e = effect(
                EffectKind::DeletePath,
                if dangerous_delete_text(&text)
                    || destructive_file_utility(&exe, &cmd.args)
                    || (exe == "find" && cmd.args.iter().any(|a| a == "-delete"))
                    || path_is_broad_or_outside(path.as_deref(), sandbox)
                {
                    Risk::Critical
                } else {
                    Risk::Medium
                },
                "command deletes filesystem paths",
                cmd.span.clone(),
            );
            e.path = path;
            out.push(e);
        }

        if is_file_write_command(&exe, &cmd.args) {
            let path = likely_path_arg(&cmd.args);
            let outside = path
                .as_deref()
                .map(|p| !path_inside_write_roots(p, sandbox) || is_home_dotfile(p))
                .unwrap_or(false);
            let critical = path
                .as_deref()
                .map(|p| outside && (is_home_dotfile(p) || p.starts_with("../")))
                .unwrap_or(false);
            let low_risk_workspace_write = path
                .as_deref()
                .map(|p| {
                    !outside
                        && matches!(exe.as_str(), "touch" | "mkdir")
                        && (p.starts_with("target/") || p.starts_with("reports/"))
                })
                .unwrap_or(false);
            let mut e = effect(
                if outside {
                    EffectKind::WorkspaceEscape
                } else {
                    EffectKind::WriteFile
                },
                if critical {
                    Risk::Critical
                } else if outside {
                    Risk::High
                } else if low_risk_workspace_write {
                    Risk::Low
                } else {
                    Risk::Medium
                },
                if outside {
                    "command writes outside configured workspace roots"
                } else {
                    "command mutates local workspace files"
                },
                cmd.span.clone(),
            );
            e.path = path;
            out.push(e);
        }

        if is_local_execution(&exe) && !executes_project_code(&exe, &cmd.args) {
            out.push(effect(
                EffectKind::ExecuteLocal,
                Risk::Medium,
                "command executes a local script or shell interpreter",
                cmd.span.clone(),
            ));
        }

        if executes_project_code(&exe, &cmd.args) {
            out.push(effect(
                EffectKind::ExecuteProjectCode,
                Risk::Medium,
                "command executes project code, tests, build scripts, or package lifecycle scripts",
                cmd.span.clone(),
            ));
        }

        if is_remote_shell_execution(full_command)
            || is_downloaded_or_encoded_exec(&text)
            || process_substitution_download_exec(&text)
            || here_string_download_exec(&text)
        {
            out.push(effect(
                EffectKind::ExecuteDownloadedCode,
                Risk::Critical,
                "downloaded or obfuscated code is executed by a shell/interpreter",
                cmd.span.clone(),
            ));
        }

        if is_obfuscated_execution(&text) {
            out.push(effect(
                EffectKind::ObfuscatedExecution,
                if critical_dynamic_execution(&text) {
                    Risk::Critical
                } else {
                    Risk::High
                },
                "command hides executable content behind eval, base64, or dynamic execution",
                cmd.span.clone(),
            ));
        }

        if has_wrapper_shell_escape(&exe, &cmd.args, &cmd.span.text) {
            out.push(effect(
                EffectKind::ObfuscatedExecution,
                Risk::Critical,
                "allowed-looking command delegates execution through a shell wrapper flag",
                cmd.span.clone(),
            ));
            if contains_url(&cmd.span.text) {
                let mut e = effect(
                    EffectKind::NetworkRead,
                    if sandbox.network {
                        Risk::Medium
                    } else {
                        Risk::High
                    },
                    "wrapper argument contains a network source",
                    cmd.span.clone(),
                );
                e.target = extract_url(&cmd.span.text);
                out.push(e);
            }
            if is_remote_shell_execution(&cmd.span.text) {
                out.push(effect(
                    EffectKind::ExecuteDownloadedCode,
                    Risk::Critical,
                    "wrapper flag can execute network-fetched shell code",
                    cmd.span.clone(),
                ));
            }
        }

        if is_git_remote_mutation(&exe, &cmd.args, &text) {
            out.push(effect(
                EffectKind::GitRemoteMutation,
                Risk::Critical,
                "command mutates remote git state or rewrites history",
                cmd.span.clone(),
            ));
        }

        if is_git_local_mutation(&exe, &cmd.args) {
            out.push(effect(
                EffectKind::WriteFile,
                Risk::Medium,
                "git command mutates local repository index, config, refs, or commit state",
                cmd.span.clone(),
            ));
        }

        if let Some(risk) = infra_risk(&exe, &cmd.args) {
            out.push(effect(
                EffectKind::InfraMutation,
                risk,
                "command can mutate cloud, container, orchestration, or infrastructure state",
                cmd.span.clone(),
            ));
        }

        if is_database_mutation(&exe, &args) {
            out.push(effect(
                EffectKind::DatabaseMutation,
                Risk::Critical,
                "command can mutate or destroy database state",
                cmd.span.clone(),
            ));
        }

        if let Some(risk) = privileged_risk(&exe, &args) {
            out.push(effect(
                EffectKind::PrivilegedHostAction,
                risk,
                "command requests elevated or host-level privileges",
                cmd.span.clone(),
            ));
        }

        if !is_known_benign(&exe, &cmd.args)
            && out
                .iter()
                .all(|e| e.span.start != cmd.span.start || e.kind == EffectKind::Pipeline)
        {
            out.push(effect(
                EffectKind::UnknownExecution,
                Risk::Medium,
                "unrecognized executable needs human review before autonomous execution",
                cmd.span.clone(),
            ));
        }
    }
}

fn collect_redirect_effects(command: &str, sandbox: &Sandbox, out: &mut Vec<Effect>) {
    for (op, target) in redirect_targets(command) {
        let outside = !path_inside_write_roots(&target, sandbox) || is_home_dotfile(&target);
        let critical = outside && (is_home_dotfile(&target) || target.starts_with("../"));
        let mut e = effect(
            if outside {
                EffectKind::WorkspaceEscape
            } else {
                EffectKind::WriteFile
            },
            if critical {
                Risk::Critical
            } else if outside {
                Risk::High
            } else {
                Risk::Low
            },
            if outside {
                "redirection writes outside configured workspace roots"
            } else {
                "redirection writes local file content"
            },
            Span {
                start: op.0,
                end: op.1,
                text: command[op.0..op.1].to_string(),
            },
        );
        e.path = Some(target);
        out.push(e);
    }
}

fn infer_flows(effects: &[Effect], command: &str) -> Vec<Flow> {
    let mut flows = Vec::new();
    let has_pipeline =
        effects.iter().any(|e| e.kind == EffectKind::Pipeline) || command.contains('|');
    let has_secret = effects.iter().any(|e| e.kind == EffectKind::SecretRead);
    let has_network_write = effects
        .iter()
        .any(|e| e.kind == EffectKind::NetworkWrite || e.kind == EffectKind::NetworkRead);
    let has_network_read = effects.iter().any(|e| e.kind == EffectKind::NetworkRead);
    let has_execution = effects
        .iter()
        .any(|e| e.kind == EffectKind::ExecuteLocal || e.kind == EffectKind::ExecuteDownloadedCode);
    let has_network_file_write =
        has_network_read && effects.iter().any(|e| e.kind == EffectKind::WriteFile);
    let has_later_local_exec = effects.iter().any(|e| e.kind == EffectKind::ExecuteLocal);

    if has_pipeline && has_secret && has_network_write {
        flows.push(Flow {
            from_effect: EffectKind::SecretRead,
            to_effect: EffectKind::NetworkWrite,
            evidence: "secret-like material can flow through a pipeline into a network command"
                .to_string(),
            risk: Risk::Critical,
        });
    }

    if has_pipeline && has_network_read && has_execution {
        flows.push(Flow {
            from_effect: EffectKind::NetworkRead,
            to_effect: EffectKind::ExecuteLocal,
            evidence: "network-fetched bytes can flow into an interpreter or shell".to_string(),
            risk: Risk::Critical,
        });
    }

    if has_network_file_write
        && has_later_local_exec
        && (command.contains("&&") || command.contains(";"))
    {
        flows.push(Flow {
            from_effect: EffectKind::NetworkRead,
            to_effect: EffectKind::ExecuteLocal,
            evidence: "network-fetched content is written locally and later executed in the same command chain".to_string(),
            risk: Risk::Critical,
        });
    }

    flows
}

fn command_node_from_text(text: &str, offset: usize) -> CommandNode {
    parse_command_text(text, offset).unwrap_or_else(|| CommandNode {
        executable: text.trim().to_string(),
        args: vec![],
        span: Span {
            start: offset,
            end: offset + text.len(),
            text: text.to_string(),
        },
    })
}

fn parse_command_text(text: &str, offset: usize) -> Option<CommandNode> {
    let tokens = shell_words(text);
    let executable = tokens
        .iter()
        .find(|t| !t.contains('=') && !t.starts_with('-'))?
        .clone();
    let exec_index = tokens.iter().position(|t| t == &executable).unwrap_or(0);
    let args = tokens.into_iter().skip(exec_index + 1).collect();
    Some(CommandNode {
        executable,
        args,
        span: Span {
            start: offset,
            end: offset + text.len(),
            text: text.to_string(),
        },
    })
}

fn shell_words(text: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for ch in text.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            current.push(ch);
            continue;
        }
        if let Some(q) = quote {
            if ch == q {
                quote = None;
            } else {
                current.push(ch);
            }
            continue;
        }
        if ch == '\'' || ch == '"' {
            quote = Some(ch);
            continue;
        }
        if ch.is_whitespace() || matches!(ch, '|' | ';' | '&') {
            if !current.is_empty() {
                words.push(current.clone());
                current.clear();
            }
            continue;
        }
        current.push(ch);
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

fn node_text(node: Node, source: &str) -> String {
    source[node.start_byte()..node.end_byte()].to_string()
}

fn span_for(node: Node, source: &str) -> Span {
    Span {
        start: node.start_byte(),
        end: node.end_byte(),
        text: node_text(node, source),
    }
}

fn effect(kind: EffectKind, risk: Risk, evidence: &str, span: Span) -> Effect {
    Effect {
        kind,
        risk,
        evidence: evidence.to_string(),
        path: None,
        target: None,
        source: None,
        span,
    }
}

fn dedupe_commands(commands: &mut Vec<CommandNode>) {
    let mut seen = BTreeSet::new();
    commands.retain(|cmd| seen.insert((cmd.span.start, cmd.span.end, cmd.executable.clone())));
}

fn dedupe_effects(effects: &mut Vec<Effect>) {
    let mut seen = BTreeSet::new();
    effects.retain(|effect| {
        seen.insert((
            effect.kind.clone(),
            effect.span.start,
            effect.span.end,
            effect.path.clone(),
            effect.target.clone(),
        ))
    });
    effects.sort_by_key(|e| (e.span.start, format!("{:?}", e.kind)));
}

fn dedupe_redirects(redirects: &mut Vec<RedirectNode>) {
    let mut seen = BTreeSet::new();
    redirects.retain(|redirect| {
        seen.insert((
            redirect.span.start,
            redirect.span.end,
            redirect.op.clone(),
            redirect.target.clone(),
        ))
    });
    redirects.sort_by_key(|r| (r.span.start, r.span.end));
}

fn contains_url(text: &str) -> bool {
    text.contains("http://") || text.contains("https://")
}

fn extract_url(text: &str) -> Option<String> {
    text.split_whitespace()
        .find(|part| part.starts_with("http://") || part.starts_with("https://"))
        .map(|s| {
            s.trim_matches(|c| c == '"' || c == '\'' || c == ')' || c == ';')
                .to_string()
        })
}

fn looks_like_network_write(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("-d ")
        || lower.contains("--data")
        || lower.contains("-x post")
        || lower.contains("request post")
        || lower.contains(" upload")
}

fn is_package_manager_install(exe: &str, args: &str) -> bool {
    matches!(exe, "npm" | "pnpm" | "yarn")
        && (args.contains(" install")
            || args.starts_with("install")
            || args.contains(" add")
            || args.starts_with("add"))
        || exe == "pip" && args.starts_with("install")
        || exe == "uv" && args.starts_with("add")
        || exe == "poetry" && args.starts_with("add")
        || exe == "cargo" && args.starts_with("add")
        || exe == "go" && args.starts_with("get")
        || exe == "brew" && args.starts_with("install")
        || (exe == "apt" || exe == "apt-get") && args.contains("install")
}

fn is_package_registry_mutation(exe: &str, args: &[String]) -> bool {
    (exe == "npm"
        && args
            .get(0)
            .map(|a| matches!(a.as_str(), "publish" | "version"))
            .unwrap_or(false))
        || (exe == "npm"
            && args.get(0).map(String::as_str) == Some("audit")
            && args.iter().any(|a| a == "fix"))
        || (exe == "cargo"
            && args
                .get(0)
                .map(|a| matches!(a.as_str(), "publish" | "yank"))
                .unwrap_or(false))
}

fn is_package_metadata_network(exe: &str, args: &[String]) -> bool {
    (exe == "npm" && args.get(0).map(String::as_str) == Some("view"))
        || (exe == "cargo" && args.get(0).map(String::as_str) == Some("search"))
        || (exe == "pip" && args.get(0).map(String::as_str) == Some("index"))
        || (exe == "go" && args.get(0).map(String::as_str) == Some("install"))
}

fn network_output_path(exe: &str, args: &[String]) -> Option<String> {
    if exe == "curl" {
        for idx in 0..args.len() {
            if (args[idx] == "-o" || args[idx] == "--output") && idx + 1 < args.len() {
                return Some(args[idx + 1].clone());
            }
        }
    }
    if exe == "wget" {
        for idx in 0..args.len() {
            if (args[idx] == "-O" || args[idx] == "--output-document") && idx + 1 < args.len() {
                return Some(args[idx + 1].clone());
            }
        }
    }
    None
}

fn is_secret_read_command(exe: &str, args: &[String]) -> bool {
    (exe == "cat"
        || exe == "less"
        || exe == "head"
        || exe == "tail"
        || exe == "sed"
        || exe == "grep")
        && args.iter().any(|arg| is_secret_path(arg))
}

fn mentions_secret(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    [
        ".env",
        ".ssh",
        "id_rsa",
        "id_ed25519",
        ".aws/credentials",
        ".npmrc",
        ".pypirc",
        "gh auth token",
        "printenv",
        "op item get",
        "pass show",
        "secret",
        "api_key",
        "token",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn first_secret_path(text: &str) -> Option<String> {
    shell_words(text).into_iter().find(|w| is_secret_path(w))
}

fn is_secret_path(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    p.contains(".env")
        || p.contains("id_rsa")
        || p.contains("id_ed25519")
        || p.contains(".aws/credentials")
        || p.contains(".npmrc")
        || p.contains(".pypirc")
        || p.contains(".ssh")
        || p.contains("secret")
        || p.contains("token")
}

fn credential_probe(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("select token")
        || lower.contains("select secret")
        || lower.contains("auth token")
}

fn secret_copy_outside(exe: &str, args: &[String], sandbox: &Sandbox) -> bool {
    if exe != "cp" && exe != "mv" {
        return false;
    }
    let source_secret = args.iter().any(|arg| is_secret_path(arg));
    let dest_outside = args
        .iter()
        .rev()
        .find(|arg| !arg.starts_with('-'))
        .map(|dest| !path_inside_write_roots(dest, sandbox))
        .unwrap_or(false);
    source_secret && dest_outside
}

fn secret_exfiltration_text(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    ((lower.contains(".env")
        || lower.contains(".ssh")
        || lower.contains("printenv")
        || lower.starts_with("env ")
        || lower.contains(" env "))
        && (lower.contains("curl ")
            || lower.contains(" nc ")
            || lower.contains("netcat")
            || lower.contains("scp ")))
        || (lower.contains("proxycommand")
            && (lower.contains(".env") || lower.contains("token") || lower.contains("secret")))
}

fn is_delete_command(exe: &str, args: &[String]) -> bool {
    exe == "rm" || exe == "unlink" || (exe == "find" && args.iter().any(|a| a == "-delete"))
}

fn destructive_file_utility(exe: &str, args: &[String]) -> bool {
    exe == "shred"
        || exe == "truncate"
        || exe == "dd"
        || (exe == "rsync" && args.iter().any(|a| a == "--delete"))
        || (exe == "chmod" && args.iter().any(|a| a.contains("777")))
}

fn dangerous_delete_text(text: &str) -> bool {
    let words = shell_words(text);
    for window in words.windows(3) {
        if (window[0] == "rm" || window[0] == "sudo")
            && (window[1] == "-rf" || window[1] == "-fr")
            && matches!(window[2].as_str(), "/" | "~/" | "~" | ".git")
        {
            return true;
        }
    }
    words.windows(4).any(|w| {
        w[0] == "sudo"
            && w[1] == "rm"
            && (w[2] == "-rf" || w[2] == "-fr")
            && matches!(w[3].as_str(), "/" | "~/" | "~" | ".git")
    })
}

fn is_file_write_command(exe: &str, args: &[String]) -> bool {
    matches!(exe, "touch" | "mkdir" | "cp" | "mv" | "tee" | "install")
        || (exe == "sed" && args.iter().any(|a| a == "-i" || a.starts_with("-i")))
        || (exe == "perl" && args.iter().any(|a| a == "-pi" || a.contains('i')))
        || (exe == "ruff" && args.iter().any(|a| a == "format" || a == "--fix"))
}

fn likely_path_arg(args: &[String]) -> Option<String> {
    if args
        .iter()
        .any(|a| a.starts_with("~/") || a.starts_with("/"))
    {
        return args
            .iter()
            .find(|arg| arg.starts_with("~/") || arg.starts_with('/'))
            .cloned();
    }
    args.iter()
        .rev()
        .find(|arg| !arg.starts_with('-') && !arg.contains('='))
        .cloned()
}

fn path_is_broad_or_outside(path: Option<&str>, sandbox: &Sandbox) -> bool {
    let Some(path) = path else {
        return true;
    };
    matches!(path, "/" | "~" | "~/" | ".git")
        || path.starts_with("/etc")
        || path.starts_with("/usr")
        || path.starts_with("/var")
        || !path_inside_write_roots(path, sandbox)
}

fn is_home_dotfile(path: &str) -> bool {
    path.starts_with("~/")
        || path.starts_with("$HOME/")
        || path.starts_with("${HOME}/")
            && (path.contains(".zshrc")
                || path.contains(".bashrc")
                || path.contains(".profile")
                || path.contains(".ssh/")
                || path.contains(".config/"))
}

fn path_inside_write_roots(path: &str, sandbox: &Sandbox) -> bool {
    let normalized = normalize_path(path, &sandbox.workspace);
    sandbox
        .write_roots
        .iter()
        .map(|root| normalize_path(root, &sandbox.workspace))
        .any(|root| {
            normalized == root
                || normalized.starts_with(&(root.trim_end_matches('/').to_string() + "/"))
        })
}

fn normalize_path(path: &str, workspace: &str) -> String {
    let raw = path.trim_matches('"').trim_matches('\'');
    let joined = if raw.starts_with('/') {
        PathBuf::from(raw)
    } else if raw.starts_with("~/") || raw == "~" {
        PathBuf::from(raw.replacen('~', "/home/user", 1))
    } else {
        Path::new(workspace).join(raw)
    };

    let mut normalized = PathBuf::new();
    for component in joined.components() {
        match component {
            Component::ParentDir => {
                normalized.pop();
            }
            Component::CurDir => {}
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized.to_string_lossy().to_string()
}

fn is_local_execution(exe: &str) -> bool {
    matches!(
        exe,
        "bash" | "sh" | "zsh" | "python" | "python3" | "ruby" | "node" | "perl"
    )
}

fn executes_project_code(exe: &str, args: &[String]) -> bool {
    exe == "pytest"
        || exe == "make"
            && args
                .iter()
                .any(|a| a.contains("test") || a.contains("check") || a.contains("build"))
        || exe == "cargo"
            && args
                .iter()
                .any(|a| matches!(a.as_str(), "test" | "check" | "build" | "clippy"))
        || exe == "npm" && args.iter().any(|a| matches!(a.as_str(), "test" | "run"))
        || exe == "pnpm" && args.iter().any(|a| matches!(a.as_str(), "test" | "run"))
        || exe == "yarn" && args.iter().any(|a| matches!(a.as_str(), "test" | "run"))
        || exe == "go" && args.iter().any(|a| a == "test" || a == "run")
        || exe == "cargo" && args.iter().any(|a| a == "run")
        || (exe == "python" || exe == "python3")
            && args.iter().any(|a| a.ends_with(".py") || a == "-m")
        || exe == "docker" && args.iter().any(|a| a == "build")
}

fn is_remote_shell_execution(command: &str) -> bool {
    let lower = command.to_ascii_lowercase();
    (lower.contains("curl ")
        || lower.contains("wget ")
        || lower.contains("https://")
        || lower.contains("http://"))
        && (lower.contains("| sh")
            || lower.contains("|sh")
            || lower.contains("| bash")
            || lower.contains("|bash")
            || lower.contains("bash <(")
            || lower.contains("sh <(")
            || lower.contains("eval $(")
            || lower.contains("eval \"$("))
}

fn is_obfuscated_execution(text: &str) -> bool {
    text.contains("eval ")
        || text.contains("base64 -d")
        || text.contains("base64 --decode")
        || text.contains("python -c")
        || text.contains("sh -c")
        || text.contains("bash -c")
        || text.contains("exec(")
        || text.contains("<(")
}

fn is_downloaded_or_encoded_exec(text: &str) -> bool {
    text.contains("base64 -d")
        || text.contains("base64 --decode")
        || (text.contains("exec(")
            && (text.contains("http://") || text.contains("https://") || text.contains("urlopen")))
        || (text.contains("bash_env") && (text.contains("http://") || text.contains("https://")))
}

fn process_substitution_download_exec(text: &str) -> bool {
    text.contains("<(curl") || text.contains("<(wget")
}

fn here_string_download_exec(text: &str) -> bool {
    text.contains("<<<")
        && (text.contains("curl ")
            || text.contains("wget ")
            || text.contains("https://")
            || text.contains("http://"))
}

fn critical_dynamic_execution(text: &str) -> bool {
    text.contains("eval ")
        || text.contains("os.system")
        || text.contains("system(")
        || text.contains("bash_env")
        || text.contains("rm -rf")
}

fn has_wrapper_shell_escape(exe: &str, args: &[String], text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    (exe == "go" && args.iter().any(|a| a == "-exec" || a.starts_with("-exec=")))
        || (exe == "rg" && args.iter().any(|a| a == "--pre" || a.starts_with("--pre=")))
        || (exe == "grep"
            && args
                .iter()
                .any(|a| a == "--include" && lower.contains("sh -c")))
        || (exe == "find" && args.iter().any(|a| a == "-exec"))
        || (exe == "tar"
            && args
                .iter()
                .any(|a| a.starts_with("--checkpoint-action=exec")))
        || (exe == "ssh" && lower.contains("proxycommand"))
        || (exe == "xargs" && lower.contains("sh -c"))
        || (exe == "perl" && lower.contains("system("))
}

fn is_git_remote_mutation(exe: &str, args: &[String], text: &str) -> bool {
    exe == "git"
        && ((args.get(0).map(String::as_str) == Some("push"))
            || (args.get(0).map(String::as_str) == Some("reset")
                && args.iter().any(|a| a == "--hard"))
            || (args.get(0).map(String::as_str) == Some("clean")
                && args.iter().any(|a| a.contains('x')))
            || (args.get(0).map(String::as_str) == Some("update-ref"))
            || (text.contains("alias.") && text.contains("push --force"))
            || (text.contains("core.sshcommand") && text.contains("proxycommand")))
}

fn is_git_local_mutation(exe: &str, args: &[String]) -> bool {
    exe == "git"
        && matches!(
            args.get(0).map(String::as_str),
            Some("add" | "commit" | "config" | "checkout" | "switch" | "merge" | "rebase")
        )
}

fn infra_risk(exe: &str, args: &[String]) -> Option<Risk> {
    if matches!(exe, "terraform" | "tofu" | "pulumi") {
        if args
            .iter()
            .any(|a| matches!(a.as_str(), "destroy") || a == "-auto-approve" || a == "--yes")
        {
            return Some(Risk::Critical);
        }
        if args
            .iter()
            .any(|a| matches!(a.as_str(), "apply" | "up" | "plan"))
        {
            return Some(Risk::High);
        }
    }
    if exe == "kubectl" {
        if args.iter().any(|a| matches!(a.as_str(), "delete")) {
            return Some(Risk::Critical);
        }
        if args
            .iter()
            .any(|a| matches!(a.as_str(), "apply" | "scale" | "patch"))
        {
            return Some(Risk::High);
        }
    }
    if exe == "helm" {
        if args.iter().any(|a| matches!(a.as_str(), "uninstall")) {
            return Some(Risk::Critical);
        }
        if args
            .iter()
            .any(|a| matches!(a.as_str(), "upgrade" | "install"))
        {
            return Some(Risk::High);
        }
    }
    if exe == "docker" {
        if args.iter().any(|a| {
            a == "system" || a.contains("/:/") || a == "-v" && args.iter().any(|x| x.contains("/:"))
        }) {
            return Some(Risk::Critical);
        }
        if args.iter().any(|a| matches!(a.as_str(), "run" | "compose")) {
            return Some(Risk::High);
        }
    }
    if matches!(exe, "aws" | "gcloud" | "az") {
        if args.iter().any(|a| {
            matches!(
                a.as_str(),
                "rm" | "delete" | "destroy" | "put" | "cp" | "sync"
            )
        }) {
            return Some(Risk::Critical);
        }
        return Some(Risk::High);
    }
    if exe == "make"
        && args
            .iter()
            .any(|a| matches!(a.as_str(), "deploy" | "release" | "publish"))
    {
        return Some(Risk::Critical);
    }
    None
}

fn is_database_mutation(exe: &str, args: &str) -> bool {
    matches!(
        exe,
        "psql" | "mysql" | "sqlite" | "sqlite3" | "mongo" | "redis-cli"
    ) && [
        "drop database",
        "drop table",
        "truncate table",
        "delete from",
        "flushall",
        "drop ",
        "update ",
        "insert ",
        "alter table",
        "create table",
    ]
    .iter()
    .any(|needle| args.to_ascii_lowercase().contains(needle))
}

fn privileged_risk(exe: &str, args: &str) -> Option<Risk> {
    if exe == "sudo" || exe == "su" || exe == "chown" || exe == "systemctl" || exe == "launchctl" {
        Some(Risk::High)
    } else if exe == "chmod" && args.contains("777") {
        Some(Risk::Critical)
    } else {
        None
    }
}

fn is_known_benign(exe: &str, args: &[String]) -> bool {
    if exe == "git" {
        return matches!(
            args.get(0).map(String::as_str),
            Some("status" | "diff" | "log" | "show" | "branch" | "remote")
        );
    }
    if exe == "make" {
        return args
            .iter()
            .any(|a| matches!(a.as_str(), "test" | "check" | "build"));
    }
    matches!(
        exe,
        "rg" | "grep"
            | "ls"
            | "pwd"
            | "find"
            | "sed"
            | "head"
            | "tail"
            | "cat"
            | "wc"
            | "du"
            | "tree"
            | "cargo"
            | "npm"
            | "pnpm"
            | "yarn"
            | "pytest"
            | "python"
            | "go"
            | "ruff"
            | "mypy"
            | "printf"
            | "echo"
    ) && !is_delete_command(exe, args)
}

fn strip_wrappers(exe: &str) -> String {
    exe.trim_matches('"')
        .trim_matches('\'')
        .to_ascii_lowercase()
}

fn redirect_targets(command: &str) -> Vec<((usize, usize), String)> {
    let bytes = command.as_bytes();
    let mut targets = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'>' {
            let start = i;
            i += 1;
            if i < bytes.len() && bytes[i] == b'>' {
                i += 1;
            }
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            let target_start = i;
            while i < bytes.len()
                && !bytes[i].is_ascii_whitespace()
                && !matches!(bytes[i], b'|' | b';' | b'&')
            {
                i += 1;
            }
            if target_start < i {
                targets.push((
                    (start, i),
                    command[target_start..i]
                        .trim_matches('"')
                        .trim_matches('\'')
                        .to_string(),
                ));
            }
        } else {
            i += 1;
        }
    }
    targets
}
