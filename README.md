# php2shell-autofix

One command that finds every PHP on a Linux server (or a Mac with Homebrew) and fixes
**PHP2Shell** — CVE-2026-109618 and CVE-2026-109619, the unauthenticated remote code
execution bugs disclosed on 21 October 2026.

Fixed upstream in **PHP 8.2.35, 8.3.36, 8.4.27 and 8.5.12**. Distributions also ship
backported fixes that keep the old version number, so this script checks package
changelogs instead of trusting `php -v`.

## Run it

**One command for every PHP version** — 8.x, 7.x, 5.6, all of them:

```bash
curl -fsSL https://php2shell.wizeb.com/autofix | sudo bash
```

On macOS with Homebrew, run the same command **without** `sudo`.

That's all most servers need. It keeps you on the PHP version you have: an old
PHP 7.4 is patched to a fixed **7.4** build (from your distro, Ondřej Surý or Remi),
not upgraded to PHP 8. Want to see the plan first? Add `-s -- --dry-run`:

```bash
curl -fsSL https://php2shell.wizeb.com/autofix | sudo bash -s -- --dry-run
```

### Only if the summary tells you to: `--force`

Rarely, no patched build of your version exists for your OS (for example PHP 7.4 on
Ubuntu 20.04 without Ubuntu Pro). The summary then says so, applies a temporary
mitigation, and names the way to stay on your version (such as Ubuntu Pro). If you'd
rather upgrade PHP instead, `--force` moves it to a supported version (8.3 by default)
after checking your code:

```bash
curl -fsSL https://php2shell.wizeb.com/autofix | sudo bash -s -- --force --project /var/www/app
```

Don't use `--force` "just in case": it changes your PHP version, and old apps can break.

### Verify before you run it (optional)

`php2shell.wizeb.com/autofix` redirects to the script in this repository. To check the
download against the published checksum before running it:

```bash
curl -fsSL https://php2shell.wizeb.com/autofix -o php2shell-fix.sh
curl -fsSL https://raw.githubusercontent.com/rahnas/php2shell-autofix/main/SHA256SUMS | sha256sum -c -
sudo bash php2shell-fix.sh
```

On macOS use `shasum -a 256 -c` instead of `sha256sum -c`.

## What it does

It always uses the least invasive fix that works, and escalates only when the step
before it fails:

1. **Find** every PHP: distro packages (all versions side by side), cPanel ea-php,
   CloudLinux alt-php, Plesk, Remi SCL, LiteSpeed lsphp, Homebrew, MAMP/Herd/MacPorts,
   source builds, FrankenPHP and running Docker containers.
2. **Check** each one: version ≥ the fixed release, or both CVE ids in the package
   changelog (distro backport). Safe installs are not touched.
3. **Patch in place** from the repositories you already use, upgrading only that
   branch's PHP packages — never a full system upgrade.
4. **Same-branch repo**: if your distro has no fix, add Ondřej Surý's repository
   (Debian/Ubuntu) or Remi Collet's (RHEL/Alma/Rocky/Oracle 8 and 9) and patch the
   *same* PHP version — this covers most end-of-life versions (5.6, 7.x, 8.0, 8.1):
   a 7.4 server stays on 7.4. If that repo has no fix either, it is removed again and
   the summary names the same-version option for your OS (Ubuntu Pro — free for up to
   5 machines — on Ubuntu 16.04–20.04, Freexian ELTS on Debian 9–11, TuxCare/Zend
   elsewhere).
5. **`--force`** (opt-in, last resort): move what is still vulnerable to a supported
   branch (default 8.3).
   - `--project DIR` first runs PHPCompatibility on your code and lists what will break.
   - Same PHP extensions are installed for the new branch.
   - Your php.ini settings (memory_limit, upload sizes, timezone…) are carried over.
   - PHP-FPM pools are copied and keep their **old socket paths**, so nginx/Apache
     configs need no change. Apache mod_php is switched and config-tested.
   - The old branch stays installed (inactive) and `--rollback` undoes everything.
6. **Mitigate**: anything still vulnerable gets `session.upload_progress.enabled = 0`
   in a drop-in ini file. This only blocks part of the attack — it is removed
   automatically on a later run once PHP is patched.
7. **Restart** PHP-FPM, Apache, LiteSpeed (and cPanel's PHP-FPM) and confirm no process
   is still running the old binary.

## Options

| Option | Effect |
| --- | --- |
| `-n`, `--dry-run` | Report and show the plan; change nothing. |
| `-f`, `--force` | Move unpatchable PHP to a supported branch. **Old apps can break.** Pauses 10 s on a terminal. |
| `-t`, `--target X.Y` | Branch for `--force`: 8.2, 8.3 (default), 8.4 or 8.5. |
| `-p`, `--project DIR` | Scan DIR with PHPCompatibility before forcing. Repeatable. |
| `-y`, `--yes` | Skip the 10-second pause before `--force`. |
| `--no-restart` | Don't restart services (it still tells you what needs it). |
| `--no-mitigate` | Don't add the temporary ini mitigation. |
| `--no-docker` | Don't inspect running containers. |
| `--rollback` | Undo the `--force` changes of the last run. |

Exit code: `0` everything safe, `1` something still needs attention, `2` error.
Log: `/var/log/php2shell-fix.log` (macOS: `~/Library/Logs/php2shell-fix.log`).
Backups and the rollback script: `/var/backups/php2shell-fix/<run>/`.

## What it will not do

- Run a full system upgrade (`apt upgrade`, `pacman -Syu` only with `--force` on Arch).
- Modify Docker containers — it reports them with the image to rebuild.
- Change cPanel/Plesk per-site PHP versions — it tells you where to switch them.
- Remove the old PHP branch after `--force`.

## Tested

| System | Scenario | Result |
| --- | --- | --- |
| Ubuntu 24.04 (real server) | Ubuntu's 8.3 fix available | Patched in place, backport recognised |
| Ubuntu 22.04 | Distro fix unavailable | Sury's patched 8.1 (8.1.2 → 8.1.34), same branch |
| Ubuntu 22.04 | Sury fix blocked, `--force --project` | Moved 8.1 → 8.3: pools, sockets, mod_php, ini carried; scan flagged removed functions; `--rollback` restored 8.1 |
| Ubuntu 20.04 | EOL 7.4, Sury no longer publishes | Repo removed again, mitigation applied, `--force` advised |
| Rocky Linux 9 | Old unpatched 8.0 | Patched from Rocky's own repo |
| Rocky Linux 9 | Rocky fix hidden | Remi's patched 8.0 (`php:remi-8.0`), same branch |
| Alpine 3.18 | EOL php81 | Explains no php83 on that release; `--target 8.2` works |
| `php:7.4-fpm` image | Source build | Mitigated, told to rebuild from a newer image |
| Host with containers | Vulnerable container running | Reported with image name, not modified |
| macOS | bash 3.2 | Parses and runs; Homebrew path not yet run on a real Mac |

## Before running on production

Run `--dry-run` first, and audit any script you pipe into `sudo bash`. Publish the
script with a SHA256 checksum so others can verify it.

## License

MIT — see [LICENSE](LICENSE).
