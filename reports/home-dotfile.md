# Command Preflight Report

```bash
cargo check > ~/.zshrc
```

**Decision:** `Deny`  
**Risk:** `Critical`  
**Reason:** Command writes to a high-risk path outside the workspace, such as a parent path or home dotfile.

**Safer path:** Constrain writes to the workspace or use an explicit output file under the repo.

## Parsed Commands

- `cargo` args: `["check"]` span: `cargo check`

## Normalized Shell Structure

- redirect op=`>` target=`Some("~/.zshrc")` span=`> ~/.zshrc`

## Effects

- `ExecuteProjectCode` risk=`Medium` evidence=command executes project code, tests, build scripts, or package lifecycle scripts span=`cargo check`
- `WorkspaceEscape` risk=`Critical` evidence=redirection writes outside configured workspace roots span=`> ~/.zshrc` path=`~/.zshrc`

## Flows

- none inferred

## Policy Evidence

- rule=`allow_in_sandbox.project_code_execution` decision=`AllowInSandbox` effect=`ExecuteProjectCode` evidence=command executes project code, tests, build scripts, or package lifecycle scripts
- rule=`deny.critical_workspace_escape` decision=`Deny` effect=`WorkspaceEscape` evidence=redirection writes outside configured workspace roots

