# Forge accounts for clone, fetch and push

The Repos view (`r` on a community) can clone a community's repositories and
make commits in them sign as your persona. Reaching the forge (GitHub and the
like) is a separate question: **which forge account** git uses to clone, fetch
and push. Without a choice, git uses whatever this machine's git config says —
the global `core.sshCommand`, ssh-agent's keys, a credential helper. If you have
several accounts on one forge (a work and a personal GitHub login, say), you
can choose one per community, and override it per repository.

Commit signing is unaffected: that is did-git-sign's, and signs as the
community's persona whichever forge account pushes the commit.

## Choosing

Highlight a repository (or open it) and press **`f`**. openvtc looks for:

| Option | What it is | Over |
|---|---|---|
| **gh account** | An account the [GitHub CLI](https://cli.github.com/) holds on that forge (`gh auth status`). Needs gh 2.40 or later. | HTTPS |
| **SSH key** | A private key in `~/.ssh` named `id_*` (not the `.pub` half), or any key path you type. | SSH |
| **Git default** | Nothing written; git does what it did before. | the workspace's protocol (`w`) |
| **Same as the community's choice** | On a single repository: follow the forge-wide choice. | — |

- `↑`/`↓` choose, `Tab` switches between **this repository** and **every
  repository of this community on that forge**, `⏎` saves and applies, `Esc`
  cancels.
- If nothing is chosen yet and you linked a forge account in this session
  (`l`), the gh account with the same login is highlighted.
- A repository's own choice wins over its community's forge-wide choice.
  Choosing *Git default* on a repository opts it out of the forge-wide account.
- On a gh account, `a` switches the **commit author** between the account
  (the default) and your own git identity — see below.

Before saving, openvtc checks the choice works: the key file exists, or
`gh auth token --user <login>` answers for that account. Otherwise it says why —
"the key file … is missing", "gh is not installed", "gh has no account X logged
in on github.com", "this gh cannot choose between accounts; update gh to 2.40 or
later".

The repository's screen shows `forge account: …` and where the choice came from,
and says so when a checkout's own git config disagrees (for example a checkout
made before you chose); `f`, `⏎` writes the choice into it.

## Commit author

Pushing as an account is not enough for the forge to attribute your commits
to it: GitHub attributes a commit by its author email. With a global
`user.email` that belongs to another account, a commit pushed by `alice-work`
still shows as `alice`, and is not marked *Verified*. So choosing a gh account
also sets, in the checkout only,

```
user.name  = alice-work
user.email = 12345+alice-work@users.noreply.github.com
```

— the account's `users.noreply` address, with its numeric id looked up once
with `gh api users/alice-work` (bounded). Press `a` in the picker to keep your
own identity instead. An SSH key cannot say which account it belongs to, so it
leaves the author alone. The repository's screen shows `commits authored as:`
for a checkout.

## Push access, forks and the community's link

- After a clone or a choice, openvtc asks the forge (with that account's own
  token) whether the gh account can push to the repository. If it can only
  read, the screen says so, and **`F`** forks the repository to that account
  (`gh repo fork --remote --remote-name fork`, run in the checkout) and sets
  `remote.pushDefault = fork`, so `git push` goes to the fork. Open the pull
  request from `<login>:<branch>`.
- A community's bridge closes pull requests from a forge account that is not
  linked to a member. When the chosen gh account differs from the account
  linked for this membership (`l`), the screen warns that its pull requests
  will be closed until it is linked.

## How it is applied

**On clone** (`c`), the settings are passed as `git clone --config …`, which
writes them into the new checkout before anything is fetched — so the first
clone already uses the chosen account, and every later `git fetch`, `pull` and
`push` in that checkout does too, from openvtc or your own terminal.

**On an existing checkout**, saving a choice writes the same settings with
`git config --local` into every checkout it covers (the one repository, or every
checked-out repository of the community on that forge).

The settings written:

- **SSH key**

  ```
  core.sshCommand = ssh -i '/home/you/.ssh/id_ed25519_work' -o IdentitiesOnly=yes
  ```

  `IdentitiesOnly` stops ssh offering ssh-agent's other keys first (the forge
  would accept the first key it knows and log you in as that account).

- **gh account**

  ```
  credential.https://github.com.helper =
  credential.https://github.com.helper = !f() { test "$1" = get || exit 0; t=$(gh auth token --hostname github.com --user alice-work) || exit 1; echo username=alice-work; echo "password=$t"; }; f
  credential.https://github.com.username = alice-work
  ```

  The empty first entry resets the credential helpers inherited from your
  global and system config for that forge — `osxkeychain`, say, which may hold
  another account's cached token and would otherwise answer first. (A test
  holds this: a global helper is never consulted once an account is chosen.) The
  helper asks gh for *that* account's token each time git needs one; the token
  is never written anywhere by openvtc. (`gh auth git-credential` is not used:
  it always answers with gh's *active* account for the host.)

- **Both** also get `openvtc.forgeCredential = ssh:<path>` or `gh:<login>`. That
  is how openvtc reads back which account a checkout uses, and how it knows
  what it may remove when the choice changes. It never removes a credential
  helper it did not write; choosing an SSH key does replace the checkout's own
  `core.sshCommand`.

The choice itself is stored in the workspace settings file beside the public
config (`git-workspace.json`, or `git-workspace-<profile>.json`), under
`credentials`, keyed by community DID, then forge host or repository. It holds
references only — a key path, a gh login — never a token or key material.

## Limits

- **The account decides the protocol.** A gh account works over HTTPS only and
  an SSH key over SSH only, so a clone uses the matching one whatever the
  workspace's protocol (`w`) says. An existing checkout whose `origin` uses the
  other protocol is called out: switch it with `git remote set-url origin …`.
- **gh accounts need gh 2.40 or later** (multi-account support, `gh auth token
  --user`). gh must be on the `PATH` of whatever runs git — a GUI git client
  started outside your shell may not see it.
- **Only forges gh knows** offer gh accounts (github.com and GitHub Enterprise
  hosts you logged gh into). For any other forge, use an SSH key.
- **A passphrase-protected key** works from your terminal (ssh prompts), but
  openvtc's own clone cannot prompt: load the key into ssh-agent first
  (`ssh-add`), or use a key without a passphrase.
- Key paths containing a quote or a control character are refused, because
  they end up inside the command git runs.
