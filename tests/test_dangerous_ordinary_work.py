"""Ordinary work from a project directory is not asked about, and what is asked about is what the rules page lists.

About five hundred calls a developer makes in a day (git, npm, pnpm, yarn, pip, uv, cargo, go, make, docker, kubectl, helm,
terraform, pytest, grep, find, sed, tar, curl to public hosts, ssh to a named host, rm and mv inside the project, temporary files,
the file tools on source files) are read through the hook with --builtin-tools, on two home layouts (/Users/dev and
/home/dev). Every one is allowed. The calls that are asked about are listed apart, each one a rule of docs/rules.md: a test
of the rules that refuses ordinary work would fail here, and so would a rule that was relaxed. Every command is a string; nothing
is run."""
# ruff: noqa: E501
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from intentshield.harness import HarnessGuard, handle

LAYOUTS = [("/Users/dev", "/Users/dev/code/shop"), ("/home/dev", "/home/dev/src/shop")]

ALLOWED_COMMANDS = [
    "git status", "git status --short", "git diff", "git diff --stat HEAD~1", "git log --oneline -20",
    "git log --graph --decorate --all", "git add -A", "git add src/app.py tests/test_app.py",
    "git commit -m \"Fixed the parser\"", "git commit -am \"wip\"", "git commit --amend --no-edit",
    "git push origin feature/login", "git push -u origin feature/login", "git push origin HEAD",
    "git pull --rebase origin main", "git fetch --all --prune", "git checkout -b feature/new-thing", "git checkout main",
    "git checkout -- src/app.py", "git switch develop", "git stash", "git stash pop", "git stash list",
    "git merge origin/main", "git rebase main", "git cherry-pick abc1234", "git tag v1.2.3", "git push origin v1.2.3",
    "git branch -d feature/old", "git branch -a", "git remote -v", "git remote add origin git@github.com:me/shop.git",
    "git config user.name \"Dev Name\"", "git config user.email dev@example.org",
    "git config --global user.name \"Dev Name\"", "git config --global pull.rebase true",
    "git config --global init.defaultBranch main", "git config core.editor vim",
    "git config --global core.editor \"code --wait\"", "git config --global core.autocrlf input",
    "git config --global alias.co checkout", "git config --list", "git config --get remote.origin.url",
    "git config credential.helper osxkeychain", "git config --global credential.helper store", "git config core.pager cat",
    "git config --global push.default current", "git config --global diff.tool vimdiff",
    "git config --global merge.tool vimdiff", "git submodule update --init --recursive", "git blame src/app.py",
    "git show HEAD", "git reflog", "git bisect start", "git clean -n", "git rev-parse --show-toplevel", "npm install",
    "npm ci", "npm run build", "npm run dev", "npm test", "npm test -- --watch=false", "npm run lint -- --fix",
    "npm install --save-dev typescript", "npm outdated", "npm audit", "npm publish --dry-run", "npm run start &",
    "npx prettier --write src", "npx tsc --noEmit", "npx eslint .", "npx create-react-app my-app",
    "pnpm install --frozen-lockfile", "pnpm run build", "pnpm add -D vitest", "pnpm dlx degit user/repo my-app",
    "yarn install", "yarn add lodash", "yarn build", "yarn test --coverage", "node scripts/build.js",
    "node -e \"console.log(process.version)\"", "pip install -r requirements.txt", "pip install -e .",
    "pip install --user black", "pip list --outdated", "pip freeze > requirements.txt", "python -m venv .venv",
    "source .venv/bin/activate", "python -m pytest -q", "python manage.py migrate", "python manage.py runserver 0.0.0.0:8000",
    "python scripts/train.py --epochs 3", "python -c \"import sys; print(sys.version)\"", "python3 -m http.server 8000",
    "uv sync", "uv add requests", "uv run pytest -q tests/", "uv pip install -r requirements.txt", "uvx ruff check .",
    "pytest -q", "pytest tests/test_app.py -k login -x", "pytest --cov=src --cov-report=term-missing", "ruff check src tests",
    "ruff format .", "mypy src", "black .", "cargo build --release", "cargo test", "cargo run -- --help",
    "cargo clippy -- -D warnings", "cargo fmt", "cargo add serde", "go build ./...", "go test ./... -race", "go run main.go",
    "go mod tidy", "go vet ./...", "make", "make clean", "make test", "make -j8 build", "cmake -B build -S .",
    "cmake --build build", "mvn -q package", "./gradlew build", "docker build -t shop:dev .",
    "docker run --rm -p 3000:3000 shop:dev", "docker run -it --rm -v $(pwd):/app node:20 bash", "docker ps", "docker ps -a",
    "docker logs -f shop", "docker exec -it shop sh", "docker compose up -d", "docker compose down",
    "docker compose logs --tail=100 web", "docker images", "docker rmi shop:dev", "docker system prune -f",
    "docker stop $(docker ps -q)", "docker pull postgres:16", "docker tag shop:dev registry.example.org/shop:dev",
    "docker push registry.example.org/shop:dev", "kubectl get pods", "kubectl get pods -n staging", "kubectl get deployments",
    "kubectl describe pod web-1", "kubectl logs -f deploy/web", "kubectl apply -f k8s/deployment.yaml",
    "kubectl rollout status deploy/web", "kubectl port-forward svc/web 8080:80", "kubectl config current-context",
    "kubectl config use-context staging", "kubectl exec -it web-1 -- sh", "kubectl delete pod web-1",
    "helm install web ./chart", "helm upgrade --install web ./chart -f values.yaml", "terraform fmt", "terraform init",
    "terraform plan", "terraform validate", "grep -r TODO src", "grep -rn \"def main\" .", "grep -rn \"password\" src docs",
    "grep -rI \"api_key\" --include=*.py .", "grep -E \"^import\" src/app.py", "rg \"fn main\" src", "rg -n TODO",
    "find . -name \"*.py\"", "find . -name \"*.pyc\" -delete", "find . -type d -name __pycache__ -exec rm -rf {} +",
    "find . -name node_modules -prune -o -name \"*.js\" -print", "find . -name \"*.log\" -mtime +7 -delete",
    "find src -type f -name \"*.tmp\" -delete", "find /tmp -name \"build-*\" -mtime +1 -delete", "find . -type f -size +10M",
    "find . -name \".DS_Store\" -delete", "sed -i 's/foo/bar/g' src/app.py", "sed -i '' 's/foo/bar/g' src/app.py",
    "sed -n '1,40p' src/app.py", "awk '{print $1}' access.log", "tar czf /tmp/out.tgz src", "tar xzf release.tgz -C /tmp/x",
    "tar -tf archive.tar", "zip -r dist.zip dist", "unzip -o data.zip -d data",
    "curl -s https://api.github.com/repos/python/cpython", "curl -fsSL https://example.org/data.json -o data.json",
    "curl -sS http://localhost:8000/health",
    "curl -X POST -H \"Content-Type: application/json\" -d '{\"a\":1}' http://localhost:8000/items",
    "curl -I https://example.org", "curl -H \"Authorization: Bearer $GITHUB_TOKEN\" https://api.github.com/user",
    "curl -s https://registry.npmjs.org/left-pad | jq .version", "wget https://example.org/file.zip",
    "wget -q -O - https://example.org/index.html", "ssh dev@build.example.org ls",
    "ssh dev@build.example.org \"cd app && git pull\"", "ssh -i ~/.ssh/id_ed25519 dev@build.example.org uptime",
    "ssh -T git@github.com", "ssh-add -l", "cat ~/.ssh/config", "cat ~/.ssh/known_hosts", "cat ~/.ssh/id_ed25519.pub",
    "scp dev@build.example.org:/var/log/app.log ./app.log", "rsync -av src/ /tmp/backup/",
    "rsync -av --delete build/ /tmp/site/", "mkdir -p build/out", "mkdir -p .claude/commands", "mkdir -p ~/.config/myapp",
    "touch src/__init__.py", "cp .env.example .env", "cp -r src /tmp/src-backup", "cp README.md /tmp/",
    "mv old_name.py new_name.py", "mv src/utils.py src/helpers.py", "mv build /tmp/build-old",
    "mv ~/Downloads/data.csv data/data.csv", "rm -rf node_modules", "rm -rf dist build", "rm -rf .next",
    "rm -rf .pytest_cache __pycache__", "rm -rf build*", "rm *.pyc", "rm -f *.log", "rm -rf node_modules/.cache/*",
    "rm -rf coverage/", "rm -rf target", "rm -rf /tmp/build-123", "rm -rf /tmp/pytest-of-dev", "rm -rf $TMPDIR/scratch",
    "rm -rf ~/.cache/pip", "rm -rf ~/.npm/_cacache", "rm -rf ~/.cache/pre-commit", "rm -rf .venv",
    "rm -rf .claude/worktrees/agent-1", "rm -rf .claude/projects", "rm -f .claude/commands/old.md", "rm -rf ./build",
    "rm -rf ../shop-copy", "rm -rf src/**/__pycache__", "rmdir empty_dir", "unlink latest", "ls", "ls -la", "ls -la ~",
    "ls ~/Documents", "ls ~/.claude", "ls -R src", "ls /etc", "tree -L 2", "du -sh *", "du -sh ~/.cache", "df -h", "pwd",
    "cd ~/Documents/proj && make", "cd src && ls", "cat package.json", "cat README.md", "cat CLAUDE.md", "cat .env.example",
    "cat ~/.zshrc", "cat ~/.gitconfig", "cat /etc/hosts", "head -n 20 src/app.py", "tail -f logs/app.log", "wc -l src/*.py",
    "diff old.txt new.txt", "diff -u a.py b.py", "echo \"build/\" >> .gitignore", "echo $PATH",
    "echo \"hello\" > /tmp/hello.txt", "printf '%s\\n' a b c", "env | grep PATH", "printenv HOME", "export FOO=bar",
    "which python", "type node", "chmod +x scripts/run.sh", "chmod 755 bin/tool", "chmod 600 ~/.ssh/config",
    "chmod -R u+w build", "chown -R $USER build", "lsof -i :3000", "kill $(lsof -t -i:3000)", "kill -9 4321",
    "ps aux | grep node", "open http://localhost:3000", "brew install jq", "brew update", "sudo apt-get update",
    "sudo apt-get install -y build-essential", "sudo systemctl status nginx", "sudo systemctl restart nginx",
    "sudo journalctl -u nginx -n 50", "gh pr create --fill", "gh pr list", "gh pr view 12", "gh pr checkout 12",
    "gh issue list", "gh run list", "gh run watch", "gh auth status", "gh repo clone me/shop", "aws s3 ls",
    "aws sts get-caller-identity", "gcloud config list", "gcloud run deploy shop --source .", "vercel deploy",
    "openssl rand -hex 32", "openssl version", "openssl s_client -connect example.org:443 </dev/null", "base64 logo.png",
    "sha256sum release.tgz", "jq . package.json", "date +%s", "sleep 5", "time make build", "timeout 30 npm test",
    "bash scripts/setup.sh", "sh ./configure", "./scripts/deploy.sh staging", "xargs -n1 echo < list.txt",
    "sort -u words.txt | uniq -c", "psql -h localhost -U dev -d shop -c \"select 1\"", "sqlite3 app.db \".tables\"",
    "redis-cli ping", "mysql -u root -e \"show databases\"", "docker compose --env-file .env up -d",
    "git commit -m \"Removed rm -rf / from the docs\"", "echo \"rm -rf /\" > notes.txt", "grep -r \"rm -rf\" docs",
    "ls ~/.ssh", "chmod 700 ~/.ssh", "mkdir -p ~/.ssh", "aws configure list", "aws --profile dev s3 ls",
    "find ~ -name \"*.py\" -mtime -1", "find ~/code -name node_modules -type d -prune -exec rm -rf {} +",
    "rm ~/Downloads/foo.zip", "rm -rf ~/Downloads/old", "rm -rf ~/code/old-project", "rm ~/Desktop/*.png",
    "mv ~/Desktop/*.png ~/Pictures/", "mv ~/Downloads/*.pdf docs/", "rm -rf ~/.Trash/*",
    "rm -rf /usr/local/lib/node_modules/foo", "sudo rm -rf /usr/local/bin/foo", "rm -rf /var/tmp/x",
    "sudo rm /etc/apt/sources.list.d/x.list", "sudo mv /etc/hosts /etc/hosts.bak", "mkdir /tmp/x", "rm -rf /tmp/*",
    "rm -rf /tmp/x*", "rm -rf /var/log/*.log", "rm -rf /usr/local/share/doc/x*", "rm -rf ~/Library/Caches/com.foo.*",
    "rm -rf ~/Library/Developer/Xcode/DerivedData/*", "rm -rf ~/.gradle/caches", "rm -rf ~/.m2/repository/foo",
    "rm -rf ~/.local/share/Trash/*", "rm -rf ~/go/pkg/mod/cache", "rm -rf ~/.cargo/registry/cache",
    "rm -rf ~/.config/Code/Cache*", "rm -rf ~/Documents/old-proj", "rm -rf ~/Documents/proj/build*", "rm -rf ~/Dev*/old",
    "rm -rf ~/code/*/node_modules", "rm -rf ~/proj*", "rm -rf {P}/build*", "rm -rf ~/.cache/*", "rm -rf ~/.npm/*",
    "rm -rf ~/.cache/ms-playwright*", "mv ~/Documents/a.txt ~/Documents/b.txt", "mv ~/D*/a.txt /tmp",
    "find ~/Documents/proj -name \"*.pyc\" -delete", "find /usr/local/lib -name \"*.pyc\" -delete",
    "rm -rf ~/.claude/projects", "rm -rf ~/.claude/projects/-Users-dev-code-shop", "rm ~/.claude/history.jsonl",
    "rm -rf .claude/worktrees/*", "rm -rf .cursor/rules/old", "mv .claude/commands/a.md .claude/commands/b.md",
    "rm .gemini/tmp/x", "rm -rf ~/.codex/sessions", "find ~/.claude/projects -mtime +30 -delete",
    "find .claude/worktrees -name \"x*\" -delete", "find ~/.claude -name \"*.jsonl\" -mtime +30 -delete",
    "rm ~/.claude/*.log", "ls -la .claude/", "cp -r ~/.claude/commands /tmp/", "rm -rf ~/.claude/plugins/cache",
    "chmod -R u+w ~/.claude/projects", "touch .claude/x", "cat ~/.claude/settings.json", "cat .claude/settings.json",
    "git config core.fsmonitor true", "git config --global alias.st status",
    "git config --global core.sshCommand \"ssh -i ~/.ssh/work\"", "git -c core.pager=cat log", "git -C ../other status",
    "git -c user.name=x commit -m y", "dscacheutil -q user", "nc -zv localhost 5432",
    "ssh-keygen -t ed25519 -C \"me@example.org\" -f ~/.ssh/id_ed25519", "ssh-keygen -t ed25519 -f ./deploy_key -N \"\"",
    "pbcopy < ~/.ssh/id_ed25519.pub", "chmod 600 ~/.ssh/id_ed25519",
    "ssh-copy-id -i ~/.ssh/id_ed25519.pub dev@build.example.org", "aws sts get-caller-identity --profile dev",
    "aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin 123.dkr.ecr.us-east-1.amazonaws.com",
    "docker login", "gh auth login", "npm whoami", "kubectl create secret generic db --from-literal=password=x",
    "kubectl config view", "export KUBECONFIG=~/.kube/config", "kubectl --kubeconfig ~/.kube/config get pods",
    "chmod -R 755 .", "launchctl list", "systemctl --user restart myapp", "sudo npm install -g typescript",
    "rm -rf /tmp/tmp.*", "rm -rf \"$BUILD_DIR/out\"", "rm -rf \"$TMPDIR\"/x", "cd /tmp && rm -rf foo",
    "tar -xzf x.tgz -C ~/.local", "mkdir -p ~/.local/bin", "cp tool ~/.local/bin/", "echo 'x' > ~/.config/app/conf",
    "find ~ -name \"*.md\"", "grep -r \"foo\" ~/code/proj", "grep -rn TODO ~/Documents/proj", "open ~/Downloads/x.pdf",
    "docker run --env-file .env x", "ssh -o IdentityFile=~/.ssh/work_key dev@build.example.org", "ssh-add ~/.ssh/id_ed25519",
    "gpg --list-keys", "openssl x509 -in fullchain.pem -text -noout", "openssl genrsa -out key.pem 2048",
    "curl --cacert ca.pem https://internal.example.org", "curl --cert client.pem --key client.key https://api.example.org",
    "eval \"$(ssh-agent -s)\"", "eval \"$(pyenv init -)\"", ". ~/.cargo/env", "source ~/.nvm/nvm.sh",
    "git clone https://github.com/python/cpython.git", "git clone git@github.com:me/shop.git ~/code/shop",
    "tail -f ~/Library/Logs/x.log", "sudo lsof -i :80", "sudo killall -9 node", "sudo rm -rf /var/log/old",
    "sudo rm -rf /var/cache/apt/archives/*", "sudo apt autoremove -y", "sudo dpkg -i x.deb", "sudo mkdir -p /opt/app",
    "sudo chmod -R 755 /var/www/html", "sudo cp x /usr/local/bin/x", "sudo chmod +x /usr/local/bin/x",
    "echo \"127.0.0.1 shop.local\" | sudo tee -a /etc/hosts", "sudo sed -i 's/a/b/' /etc/nginx/nginx.conf",
    "sudo nano /etc/hosts", "sudo systemctl daemon-reload", "sudo killall -HUP mDNSResponder",
    "security find-identity -v -p codesigning", "security create-keychain -p x build.keychain",
    "xcodebuild -scheme App build", "cat ~/.zsh_history", "history | tail", "env | sort", "code ~/.zshrc", "cat cert.pem",
    "git push https://github.com/me/repo.git main", "git remote set-url origin git@github.com:me/shop.git",
    "mkdir -p ~/.config/gh", "cat ~/.config/gh/config.yml", "gcloud auth list", "gcloud config get-value project",
    "gcloud auth login", "cat ~/.aws/config", "aws configure",
]

ASKED_COMMANDS = [
    "aws s3 cp build.tgz s3://my-bucket/build.tgz", "source .env", "find ~/Downloads -name \"*.dmg\" -delete",
    "curl -sSL https://sh.rustup.rs | sh", "git push --force-with-lease origin my-feature", "git push -f origin my-feature",
    "git reset --hard HEAD", "git checkout .", "chmod 777 /tmp/x", "sudo chown -R $USER:staff /usr/local/lib/node_modules",
    "docker run -v ~/.ssh:/root/.ssh:ro alpine ls /root/.ssh", "docker run -v $HOME/.aws:/root/.aws amazon/aws-cli s3 ls",
    "scp -i ~/.ssh/id_rsa file.txt dev@build.example.org:/tmp", "sudo chown $USER /opt/app",
    "sudo chown -R www-data:www-data /var/www/html", "security unlock-keychain -p x ~/Library/Keychains/login.keychain-db",
    "security default-keychain -s ~/Library/Keychains/build.keychain", "vim ~/.zshrc", "cat server.pem",
    "rsync -avz -e \"ssh -i ~/.ssh/id_rsa\" src/ dev@build.example.org:/srv/app",
]

ALLOWED_FILE_CALLS = [
    ("Read", {"file_path": "{P}/src/main.py"}),
    ("Read", {"file_path": "{P}/README.md"}),
    ("Read", {"file_path": "{P}/package.json"}),
    ("Read", {"file_path": "{P}/.env.example"}),
    ("Read", {"file_path": "/tmp/build.log"}),
    ("Read", {"file_path": "{H}/.gitconfig"}),
    ("Read", {"file_path": "{H}/.zshrc"}),
    ("Read", {"file_path": "{H}/.ssh/config"}),
    ("Read", {"file_path": "{H}/.ssh/known_hosts"}),
    ("Read", {"file_path": "{H}/.ssh/id_ed25519.pub"}),
    ("Read", {"file_path": "{P}/tests/fixtures/sample.json"}),
    ("Read", {"file_path": "/etc/hosts"}),
    ("Read", {"file_path": "{P}/CLAUDE.md"}),
    ("Read", {"file_path": "{P}/.claude/commands/review.md"}),
    ("Read", {"file_path": "{H}/.claude/CLAUDE.md"}),
    ("Read", {"file_path": "{H}/.cache/pip/log"}),
    ("Write", {"content": "print('hi')\n", "file_path": "{P}/src/app.py"}),
    ("Write", {"content": "def test_a():\n    assert True\n", "file_path": "{P}/tests/test_app.py"}),
    ("Write", {"content": "# Notes\n", "file_path": "{P}/docs/notes.md"}),
    ("Write", {"content": "{}\n", "file_path": "{P}/package.json"}),
    ("Write", {"content": "all:\n\techo hi\n", "file_path": "{P}/Makefile"}),
    ("Write", {"content": "FROM node:20\n", "file_path": "{P}/Dockerfile"}),
    ("Write", {"content": "node_modules\n", "file_path": "{P}/.gitignore"}),
    ("Write", {"content": "API_URL=\n", "file_path": "{P}/.env.example"}),
    ("Write", {"content": "{}\n", "file_path": "{P}/.vscode/settings.json"}),
    ("Write", {"content": "Review the diff.\n", "file_path": "{P}/.claude/commands/review.md"}),
    ("Write", {"content": "Helper\n", "file_path": "{P}/.claude/agents/helper.md"}),
    ("Write", {"content": "Use tabs\n", "file_path": "{P}/.cursor/rules/style.mdc"}),
    ("Write", {"content": "Notes\n", "file_path": "{P}/.gemini/GEMINI.md"}),
    ("Write", {"content": "Notes\n", "file_path": "{H}/.claude/CLAUDE.md"}),
    ("Write", {"content": "a = 1\n", "file_path": "{H}/.config/myapp/config.toml"}),
    ("Write", {"content": "x\n", "file_path": "/tmp/notes.txt"}),
    ("Write", {"content": "{}\n", "file_path": "/tmp/scratch/out.json"}),
    ("Write", {"content": "#!/bin/sh\necho hi\n", "file_path": "{P}/scripts/run.sh"}),
    ("Write", {"content": "{}\n", "file_path": "{P}/.prettierrc"}),
    ("Write", {"content": "[project]\nname='x'\n", "file_path": "{P}/pyproject.toml"}),
    ("Write", {"content": "# Changes\n", "file_path": "{P}/CHANGELOG.md"}),
    ("Write", {"content": "not a key\n", "file_path": "{P}/tests/fixtures/id_rsa"}),
    ("Write", {"content": "Bug\n", "file_path": "{P}/.github/ISSUE_TEMPLATE/bug.md"}),
    ("Edit", {"file_path": "{P}/src/app.py", "new_string": "b", "old_string": "a"}),
    ("Edit", {"file_path": "{P}/README.md", "new_string": "y", "old_string": "x"}),
    ("Edit", {"file_path": "{P}/pyproject.toml", "new_string": "0.2", "old_string": "0.1"}),
    ("Edit", {"file_path": "{P}/.claude/commands/review.md", "new_string": "b", "old_string": "a"}),
    ("Edit", {"file_path": "{P}/src/config.ts", "new_string": "b", "old_string": "a"}),
    ("Edit", {"file_path": "/tmp/notes.txt", "new_string": "b", "old_string": "a"}),
    ("MultiEdit", {"edits": [{"new_string": "b", "old_string": "a"}], "file_path": "{P}/src/app.py"}),
    ("MultiEdit", {"edits": [{"new_string": "b", "old_string": "a"}, {"new_string": "d", "old_string": "c"}], "file_path": "{P}/src/index.ts"}),
    ("NotebookEdit", {"new_source": "print(1)", "notebook_path": "{P}/analysis.ipynb"}),
    ("Grep", {"path": "{P}/src", "pattern": "TODO"}),
    ("Grep", {"pattern": "def main"}),
    ("Grep", {"path": "{P}", "pattern": "import"}),
    ("Grep", {"path": "{P}/docs", "pattern": "password"}),
    ("Grep", {"path": "{P}/node_modules/.cache", "pattern": "foo"}),
    ("Write", {"content": "A=1\n", "file_path": "{P}/.env"}),
    ("Edit", {"file_path": "{P}/.env", "new_string": "A=2", "old_string": "A=1"}),
    ("Read", {"file_path": "{H}/.aws/config"}),
    ("Grep", {"path": "{H}/code", "pattern": "foo"}),
    ("Write", {"content": "x\n", "file_path": "{P}/tests/data/server.pem"}),
    ("Write", {"content": "x\n", "file_path": "{P}/certs/ca.pem"}),
    ("Write", {"content": "{}\n", "file_path": "{P}/config/credentials.json"}),
    ("Write", {"content": "a=1\n", "file_path": "{P}/terraform/prod.tfvars"}),
]

ASKED_FILE_CALLS = [
    ("Read", {"file_path": "{P}/.env"}),
    ("Read", {"file_path": "{H}/.npmrc"}),
    ("Grep", {"path": "{H}", "pattern": "foo"}),
    ("Write", {"content": "export A=1\n", "file_path": "{H}/.zshrc"}),
    ("Write", {"content": "npm test\n", "file_path": "{P}/.husky/pre-commit"}),
    ("Write", {"content": "on: push\n", "file_path": "{P}/.github/workflows/ci.yml"}),
    ("Write", {"content": "stages: [x]\n", "file_path": "{P}/azure-pipelines.yml"}),
    ("Read", {"file_path": "{P}/terraform/prod.tfvars"}),
]


@pytest.fixture(autouse=True)
def _own_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))


def decision(tmp_path: Path, home: str, project: str, tool: str, arguments: dict[str, Any]) -> str:
    """The verdict of the hook on one call of Claude Code, with the home of the layout named by the transcript."""
    event = {"hook_event_name": "PreToolUse", "session_id": "ordinary", "cwd": project, "tool_name": tool, "tool_input": arguments,
             "transcript_path": f"{home}/.claude/projects/p/t.jsonl", "permission_mode": "default"}
    reply = handle("claude", event, HarnessGuard(tmp_path / "hooks.db", builtin_tools=True))
    return reply["hookSpecificOutput"].get("permissionDecision", "allow") if reply else "allow"


def filled(arguments: dict[str, Any], home: str, project: str) -> dict[str, Any]:
    return {k: v.replace("{P}", project).replace("{H}", home) if isinstance(v, str) else v for k, v in arguments.items()}


@pytest.mark.parametrize("home, project", LAYOUTS)
def test_the_commands_of_a_days_work_are_allowed(tmp_path: Path, home: str, project: str):
    asked = {c: d for c in ALLOWED_COMMANDS if (d := decision(tmp_path, home, project, "Bash", {"command": c})) != "allow"}
    assert asked == {}
    assert len(ALLOWED_COMMANDS) >= 250


@pytest.mark.parametrize("home, project", LAYOUTS)
def test_the_file_tools_on_the_files_of_a_project_are_allowed(tmp_path: Path, home: str, project: str):
    refused = [(tool, args) for tool, args in ALLOWED_FILE_CALLS
               if decision(tmp_path, home, project, tool, filled(args, home, project)) != "allow"]
    assert refused == []
    assert len(ALLOWED_FILE_CALLS) >= 50


@pytest.mark.parametrize("home, project", LAYOUTS)
def test_the_commands_the_rules_page_lists_as_asks_still_ask(tmp_path: Path, home: str, project: str):
    allowed = [c for c in ASKED_COMMANDS if decision(tmp_path, home, project, "Bash", {"command": c}) != "ask"]
    assert allowed == []


@pytest.mark.parametrize("home, project", LAYOUTS)
def test_the_file_calls_the_rules_page_lists_as_asks_still_ask(tmp_path: Path, home: str, project: str):
    allowed = [(tool, args) for tool, args in ASKED_FILE_CALLS
               if decision(tmp_path, home, project, tool, filled(args, home, project)) != "ask"]
    assert allowed == []


@pytest.mark.parametrize("home, project", LAYOUTS)
def test_the_guards_own_directories_can_be_worked_in(tmp_path: Path, home: str, project: str):
    for command in ("rm -rf .claude/worktrees/x", "mkdir -p .claude/commands", "ls ~/.claude", "rm -rf ~/.claude/projects/old",
                    "mv .claude/commands/a.md .claude/commands/b.md", "find .claude/worktrees -delete", "touch .claude/commands/x.md"):
        assert decision(tmp_path, home, project, "Bash", {"command": command}) == "allow", command
    for tool, args in (("Write", {"file_path": "{P}/.claude/commands/review.md", "content": "Review the diff.\n"}),
                       ("Edit", {"file_path": "{P}/.claude/commands/review.md", "old_string": "a", "new_string": "b"}),
                       ("Write", {"file_path": "{P}/.cursor/rules/style.mdc", "content": "Use tabs\n"})):
        assert decision(tmp_path, home, project, tool, filled(args, home, project)) == "allow", args
