# docker_collect

Collecte forensique d'un hôte Docker, en local sur le serveur ou **à distance via SSH**
depuis le PC de l'analyste. En mode distant, toute la sortie est écrite sur le PC :
rien n'est écrit sur le serveur, tout passe par le flux SSH.

## Utilisation rapide

```bash
# Depuis ton PC : collecte complète du serveur, sortie dans ./docker-evidence_<host>_<date>/
./docker-collect.sh -r analyste@10.0.0.5 --case INC-2026-042 --analyst H13ris

# Clé SSH dédiée + passage par un bastion
./docker-collect.sh -r admin@srv -i ~/.ssh/ir_key --ssh-opt ProxyJump=bastion

# Lister les conteneurs du serveur
./docker-collect.sh -r admin@srv -l

# Conteneur suspect : filesystem + volumes + bind mounts
./docker-collect.sh -r admin@srv -c web --export-fs --volumes --include-binds

# En local sur le serveur (comportement historique)
sudo ./docker-collect.sh
```

## Mode distant (`-r`)

- Une seule connexion SSH (ControlMaster), réutilisée pour toutes les commandes.
- Élévation de privilèges, choisie automatiquement :
  1. connexion en `root` : pas de sudo ;
  2. sinon `sudo -n` (NOPASSWD) s'il fonctionne ;
  3. sinon le mot de passe sudo est demandé **une fois** (en masqué). Il est transmis
     ensuite par stdin (`sudo -S`), jamais en argument, et n'est écrit nulle part.
  - `--ask-sudo-pass` force la demande du mot de passe, `--no-sudo` désactive sudo
    (utilisateur du groupe `docker` : les fichiers de l'hôte, les logs bruts et les volumes
    seront alors illisibles).
- `docker save`, `docker export`, les volumes et les logs bruts sont envoyés vers stdout
  puis écrits localement.
- `collection_info.txt` enregistre l'heure du PC **et** l'heure du serveur, pour mesurer
  un éventuel décalage d'horloge.
- Pré-requis : sur le PC, `bash`, `ssh`, `tar` et `sha256sum` (pas besoin de docker) ;
  sur le serveur, un shell POSIX, `docker`, `tar` et les outils système habituels.

## Ce qui est collecté

| Étape | Contenu | Sortie |
|---|---|---|
| 1. Hôte (volatil d'abord) | `ps auxwwf`, `ps` avec heure de démarrage, `ss -tunap`/`-tulpn`/`-xap` (sinon `netstat`), `ip a`/`route`/`neigh` (sinon `ifconfig`), `iptables-save`, `ip6tables-save`, `nft`, `w`, `who`, `last`, `lastb`, `lsmod`, `mount`, `df` | `host/live/` |
| | `journalctl -u docker -u containerd`, `-u ssh -u sshd`, liste des boots | `host/journal/` |
| | `systemctl list-units/list-unit-files/list-timers`, membres du groupe `docker` | `host/persistence/` |
| | `/var/log/auth.log*`, `/var/log/secure*`, `passwd`, `group`, `sudoers`, crontabs (`/etc/cron*`, `/var/spool/cron`), `/etc/systemd/system`, `rc.local`, `ld.so.preload`, `profile.d`, `sshd_config`, `/etc/docker`, **historiques shell** et **`~/.ssh/`** (dont `authorized_keys`) de tous les comptes | `host/fs/` (+ `host/fs_listing.txt`) |
| 2. Docker | version, info, ps, images, réseaux, volumes, `system df`, `daemon.json`, `docker events` (tout ce que le daemon a en mémoire) | `host/` |
| 3-4. Conteneurs | `inspect`, `diff`, `port`, montages, `top`, `stats`, `docker logs` (stdout/stderr), logs bruts du daemon avec rotations, export du filesystem (option) | `containers/<id>_<nom>/` |
| 5. Volumes (option) | volumes nommés, bind mounts, listing MAC times avant copie | `volumes/`, `containers/*/binds/` |
| 6. Images | `docker save`, `inspect`, `history` | `images/` |
| 7. Intégrité | `SHA256SUMS`, archive `.tar.gz` et son empreinte | |

`--no-host` désactive l'étape 1, et `--journal-since -7d` limite la profondeur de journalctl.

**Durée** : par défaut, aucune limite. Tout ce que le serveur a conservé est collecté
(logs des conteneurs depuis leur création, journald, auth.log et ses rotations, wtmp,
docker events). Pour limiter : `--since`/`--until` (sortie de `docker logs` uniquement,
les fichiers bruts restent complets), `--journal-since`, `--events-days`.
⚠ `docker events` n'est conservé qu'en mémoire par le daemon (environ 1000 événements,
perdus au redémarrage de Docker).
`./docker-collect.sh -h` affiche toutes les options.

## Ce que le script ne fait pas

- **Mémoire vive** : non collectée. Si elle est requise, l'acquérir **avant tout le reste**
  (LiME ou AVML), vers un support externe ou par le réseau.
- Pas de `docker exec` dans les conteneurs, ni de `commit`, `stop` ou `restart`.

## Bonnes pratiques

- Calculer le SHA256 du script avant de l'utiliser et le noter dans le rapport.
- Un compte d'investigation dédié avec une clé SSH dédiée évite de mélanger tes connexions
  avec celles de l'attaquant dans `auth.log` et `last`.
- La connexion SSH elle-même laisse des traces sur le serveur (`auth.log`, `wtmp`, journald) :
  note l'heure et l'IP source de la collecte.
