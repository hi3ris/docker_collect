#!/usr/bin/env bash
# =============================================================================
#  docker-collect.sh — Collecte forensique d'un hôte Docker
#  - Mode local (sur le serveur) ou distant (-r user@hote : depuis le PC de
#    l'analyste via SSH, la sortie est écrite UNIQUEMENT sur le PC local)
#  - État de l'hôte collecté en premier (processus, réseau, pare-feu, sessions)
#  - Journaux système (journald docker/containerd/ssh, auth.log, secure)
#  - Comptes, historiques shell, clés SSH, persistance (cron, systemd, groupe docker)
#  - Logs de tous les conteneurs (via docker logs + fichiers bruts du daemon)
#  - Métadonnées (inspect, diff, top, ports, réseaux, volumes, events)
#  - Sauvegarde des images utilisées (docker save) pour export
#  - Export optionnel du filesystem des conteneurs (docker export)
#  - Copie optionnelle des volumes nommés / bind mounts (avec garde-fous)
#  - Journal de collecte horodaté UTC + SHA256 de chaque fichier + archive
#
#  Principe : lecture seule côté Docker. Aucun "docker commit", aucun
#  stop/restart, aucune modification des conteneurs. En mode distant, aucun
#  fichier n'est écrit sur le serveur (tout transite par le flux SSH).
# =============================================================================
set -uo pipefail

VERSION="2.0"
DOCKER="${DOCKER_BIN:-docker}"
SSH="${SSH_BIN:-ssh}"

# ---- Valeurs par défaut ------------------------------------------------------
OUTDIR=""
CASE_ID=""
ANALYST=""
CONTAINERS_IN=()
SAVE_IMAGES=1
EXPORT_FS=0
RAW_LOGS=1
ARCHIVE=1
EVENTS=1
EVENTS_DAYS=30
SINCE=""
UNTIL=""
VOLUMES=0
INCLUDE_BINDS=0
MAX_VOL_SIZE="20G"
HOST_ARTIFACTS=1
JOURNAL_SINCE=""
# Mode distant
REMOTE=""
SSH_PORT=""
SSH_KEY=""
SSH_EXTRA=()
ASK_SUDO=0
NO_SUDO=0

usage() {
cat <<EOF
docker-collect.sh v${VERSION} — collecte forensique Docker

Usage : sudo $0 [options]                 (sur le serveur)
        $0 -r user@serveur [options]      (depuis le PC de l'analyste, via SSH)

Mode distant (SSH) — la sortie est écrite sur la machine qui lance le script
  -r, --remote USER@HOTE      Serveur à collecter. Rien n'est écrit sur le serveur.
  -p, --port PORT             Port SSH
  -i, --identity CLE          Clé privée SSH
      --ssh-opt OPT           Option ssh (-o), répétable. Ex : --ssh-opt ProxyJump=bastion
      --ask-sudo-pass         Demander le mot de passe sudo distant
                              (défaut : root direct, sinon "sudo -n", sinon demande)
      --no-sudo               Pas de sudo (utilisateur du groupe docker) : les fichiers
                              de l'hôte, logs bruts et volumes seront probablement illisibles

Sélection des conteneurs (défaut : TOUS, running + stopped)
  -c, --container ID[,ID...]  ID(s) ou nom(s) de conteneur. Répétable.
  -f, --file FICHIER          Fichier contenant un ID/nom par ligne (# = commentaire)
  -l, --list                  Liste les conteneurs présents puis quitte

Sortie / dossier
  -o, --output DIR            Dossier de sortie local (défaut : ./docker-evidence_<host>_<date>)
      --case ID               Référence du dossier d'investigation
      --analyst NOM           Nom de l'analyste (chaîne de traçabilité)

Options de collecte
      --no-host               Ne pas collecter l'état / les fichiers de l'hôte (étape 1)
      --journal-since TS      Limiter journalctl (ex: "2026-09-01", "-7d"). Défaut : tout
      --since TS              Filtre docker logs (ex: 2026-10-01T00:00:00 ou 48h)
      --until TS              Filtre docker logs
      --no-images             Ne pas sauvegarder les images (docker save)
      --export-fs             Exporter le filesystem de chaque conteneur (docker export)
                              ⚠ inclut les modifs runtime, PAS les volumes. Peut être volumineux.
      --no-raw                Ne pas copier les fichiers de logs bruts du daemon
      --no-events             Ne pas collecter docker events
      --events-days N         Profondeur docker events en jours (défaut : 30)
      --no-archive            Ne pas créer l'archive .tar.gz finale

Volumes (désactivé par défaut)
      --volumes               Copier les volumes nommés des conteneurs ciblés
      --include-binds         Copier aussi les bind mounts (chemins de l'hôte). Implique --volumes.
                              Exclus d'office : /, /proc, /sys, /dev, sockets, docker.sock,
                              DockerRootDir, et tout chemin contenant le dossier de sortie.
      --max-volume-size N     Taille max par montage (ex: 500M, 20G ; 0 = illimité ; défaut 20G)
                              Au-delà : montage ignoré + listing des fichiers conservé.
  -h, --help                  Aide

⚠ Mémoire vive : non collectée par ce script. Si elle est requise, l'acquérir
  AVANT tout le reste (LiME, AVML), sur un support externe.

Exemples
  $0 -r analyste@10.0.0.5 --case INC-2026-042 --analyst H13ris
  $0 -r root@srv -i ~/.ssh/ir_key -c web --export-fs --volumes
  $0 -r admin@srv --ssh-opt ProxyJump=bastion --no-images --since 72h
  sudo $0                                   # en local sur le serveur, tout collecter
  sudo $0 -f suspects.txt --case INC-2026-042 --analyst H13ris
EOF
}

# Convertit 500M / 20G / 1T / 1024 en octets
to_bytes() {
  local v="${1^^}" n u
  [[ "$v" =~ ^([0-9]+)([KMGT]?)B?$ ]] || return 1
  n=${BASH_REMATCH[1]}; u=${BASH_REMATCH[2]}
  case "$u" in
    K) n=$(( n * 1024 )) ;;
    M) n=$(( n * 1024 ** 2 )) ;;
    G) n=$(( n * 1024 ** 3 )) ;;
    T) n=$(( n * 1024 ** 4 )) ;;
  esac
  echo "$n"
}
human() { numfmt --to=iec "$1" 2>/dev/null || echo "${1}B"; }

# ---- Parsing des arguments --------------------------------------------------
LIST_ONLY=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    -r|--remote)       REMOTE="${2:-}"; shift 2 ;;
    -p|--port)         SSH_PORT="${2:-}"; shift 2 ;;
    -i|--identity)     SSH_KEY="${2:-}"; shift 2 ;;
    --ssh-opt)         SSH_EXTRA+=("${2:-}"); shift 2 ;;
    --ask-sudo-pass)   ASK_SUDO=1; shift ;;
    --no-sudo)         NO_SUDO=1; shift ;;
    -c|--container)
      [[ -z "${2:-}" ]] && { echo "Erreur : $1 requiert une valeur" >&2; exit 1; }
      IFS=',' read -ra _ids <<< "$2"; CONTAINERS_IN+=("${_ids[@]}"); shift 2 ;;
    -f|--file)
      [[ -r "${2:-}" ]] || { echo "Erreur : fichier illisible : ${2:-}" >&2; exit 1; }
      while IFS= read -r line; do
        line="${line%%#*}"; line="$(echo "$line" | tr -d '[:space:]')"
        [[ -n "$line" ]] && CONTAINERS_IN+=("$line")
      done < "$2"; shift 2 ;;
    -l|--list)         LIST_ONLY=1; shift ;;
    -o|--output)       OUTDIR="${2:-}"; shift 2 ;;
    --case)            CASE_ID="${2:-}"; shift 2 ;;
    --analyst)         ANALYST="${2:-}"; shift 2 ;;
    --no-host)         HOST_ARTIFACTS=0; shift ;;
    --journal-since)   JOURNAL_SINCE="${2:-}"; shift 2 ;;
    --since)           SINCE="${2:-}"; shift 2 ;;
    --until)           UNTIL="${2:-}"; shift 2 ;;
    --no-images)       SAVE_IMAGES=0; shift ;;
    --export-fs)       EXPORT_FS=1; shift ;;
    --no-raw)          RAW_LOGS=0; shift ;;
    --no-events)       EVENTS=0; shift ;;
    --events-days)     EVENTS_DAYS="${2:-30}"; shift 2 ;;
    --no-archive)      ARCHIVE=0; shift ;;
    --volumes)         VOLUMES=1; shift ;;
    --include-binds)   VOLUMES=1; INCLUDE_BINDS=1; shift ;;
    --max-volume-size) MAX_VOL_SIZE="${2:-}"; shift 2 ;;
    -h|--help)         usage; exit 0 ;;
    *) echo "Option inconnue : $1" >&2; usage; exit 1 ;;
  esac
done

MAX_BYTES="$(to_bytes "$MAX_VOL_SIZE")" || { echo "Erreur : --max-volume-size invalide : $MAX_VOL_SIZE" >&2; exit 1; }

# ---- Exécution locale / distante -------------------------------------------
# rhost <cmd...>   : exécute une commande sur l'hôte cible (local, ou via SSH)
# rdocker <args...>: exécute docker sur l'hôte cible
# En mode distant, stdout/stderr reviennent par SSH : rien n'est écrit sur le serveur.
SUDO=()
SUDO_PASS=""
SSH_OPTS=()
SSH_CTL_DIR=""

# Quote POSIX (sûr pour le shell distant, quel que soit le contenu)
q() { local s="${1//\'/\'\"\'\"\'}"; printf "'%s'" "$s"; }

rhost() {
  if [[ -z "$REMOTE" ]]; then "$@"; return; fi
  local cmd="" a
  for a in "${SUDO[@]}" "$@"; do cmd+="$(q "$a") "; done
  if [[ -n "$SUDO_PASS" ]]; then
    printf '%s\n' "$SUDO_PASS" | "$SSH" "${SSH_OPTS[@]}" "$REMOTE" "$cmd"
  else
    "$SSH" -n "${SSH_OPTS[@]}" "$REMOTE" "$cmd"
  fi
}
rdocker() { rhost "$DOCKER" "$@"; }

ssh_cleanup() {
  [[ -n "$SSH_CTL_DIR" ]] || return 0
  "$SSH" "${SSH_OPTS[@]}" -O exit "$REMOTE" >/dev/null 2>&1
  rm -rf "$SSH_CTL_DIR"
}

if [[ -n "$REMOTE" ]]; then
  command -v "$SSH" >/dev/null 2>&1 || { echo "Erreur : ssh introuvable" >&2; exit 1; }
  # Connexion maître unique (une seule authentification, commandes rapides)
  SSH_CTL_DIR="$(mktemp -d "${TMPDIR:-/tmp}/dcollect.XXXXXX")" || exit 1
  SSH_OPTS=(-o "ControlPath=$SSH_CTL_DIR/cm" -o ServerAliveInterval=30 -o LogLevel=ERROR)
  [[ -n "$SSH_PORT" ]] && SSH_OPTS+=(-p "$SSH_PORT")
  [[ -n "$SSH_KEY"  ]] && SSH_OPTS+=(-i "$SSH_KEY")
  for o in "${SSH_EXTRA[@]}"; do SSH_OPTS+=(-o "$o"); done
  trap ssh_cleanup EXIT
  echo "Connexion SSH à $REMOTE ..." >&2
  "$SSH" -M -f -N -o ControlPersist=yes "${SSH_OPTS[@]}" "$REMOTE" \
    || { echo "Erreur : connexion SSH impossible vers $REMOTE" >&2; exit 1; }

  # Élévation de privilèges distante
  if [[ $NO_SUDO -eq 1 ]]; then
    :
  elif [[ "$(rhost id -u 2>/dev/null)" == "0" ]]; then
    :
  elif [[ $ASK_SUDO -eq 0 ]] && rhost sudo -n true 2>/dev/null; then
    SUDO=(sudo -n)
  else
    [[ -t 0 ]] || { echo "Erreur : sudo distant demande un mot de passe (lancer dans un terminal, ou --no-sudo)" >&2; exit 1; }
    read -rsp "Mot de passe sudo pour $REMOTE : " SUDO_PASS; echo >&2
    SUDO=(sudo -S -p '')
    rhost true 2>/dev/null || { echo "Erreur : authentification sudo refusée" >&2; exit 1; }
  fi
else
  command -v "$DOCKER" >/dev/null 2>&1 || { echo "Erreur : docker introuvable" >&2; exit 1; }
fi

# ---- Pré-requis -------------------------------------------------------------
rdocker info >/dev/null 2>&1 || { echo "Erreur : impossible de joindre le daemon Docker${REMOTE:+ sur $REMOTE} (droits ? socket ?)" >&2; exit 1; }
command -v sha256sum >/dev/null 2>&1 || { echo "Erreur : sha256sum introuvable" >&2; exit 1; }

if [[ $LIST_ONLY -eq 1 ]]; then
  rdocker ps -a --no-trunc --format 'table {{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.CreatedAt}}'
  exit 0
fi

DOCKER_ROOT="$(rdocker info -f '{{.DockerRootDir}}' 2>/dev/null)"
TARGET_UID="$(rhost id -u 2>/dev/null)"

# Options tar (côté cible) : propriétaires numériques, xattrs, ACL ; ne pas traverser les FS
TAR_OPTS=(--numeric-owner --one-file-system)
TAR_HELP="$(rhost tar --help 2>/dev/null)"
if grep -q -- '--xattrs' <<< "$TAR_HELP"; then TAR_OPTS+=(--xattrs --xattrs-include='*'); fi
if grep -q -- '--acls'   <<< "$TAR_HELP"; then TAR_OPTS+=(--acls); fi

HOST="$(rhost hostname 2>/dev/null || echo unknown)"
START_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
[[ -z "$OUTDIR" ]] && OUTDIR="./docker-evidence_$(echo "$HOST" | tr -c 'A-Za-z0-9._-' '_' | sed 's/_*$//')_${STAMP}"

if [[ -e "$OUTDIR" && -n "$(ls -A "$OUTDIR" 2>/dev/null)" ]]; then
  echo "Erreur : $OUTDIR existe et n'est pas vide (pas d'écrasement de preuves)." >&2; exit 1
fi
mkdir -p "$OUTDIR"/{host,containers,images,volumes} || exit 1
OUTDIR="$(cd "$OUTDIR" && pwd)"
LOG="$OUTDIR/collection.log"
ERR="$OUTDIR/errors.log"
: > "$LOG"; : > "$ERR"

# ---- Helpers ----------------------------------------------------------------
log()  { printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | tee -a "$LOG" >&2; }
warn() { log "WARN: $*"; }
# capture <fichier_sortie> <commande...>  — trace la commande, stderr -> errors.log
capture() {
  local out="$1"; shift
  printf '[%s] CMD: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >> "$LOG"
  if ! "$@" > "$out" 2>>"$ERR"; then warn "échec : $* (voir errors.log)"; return 1; fi
}
safe_name() { echo "$1" | tr -c 'A-Za-z0-9._-' '_' | sed 's/_*$//'; }

# fetch <dossier_cible> <dossier_local> <chemin_relatif...>
# Copie des fichiers de la cible via un flux tar (préserve les mtime)
fetch() {
  local src="$1" dest="$2"; shift 2
  mkdir -p "$dest"
  printf '[%s] CMD: rhost tar -C %s -cf - %s | tar -x -C %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$src" "$*" "$dest" >> "$LOG"
  rhost tar --numeric-owner --ignore-failed-read -C "$src" -cf - "$@" 2>>"$ERR" \
    | tar -xf - -C "$dest" 2>>"$ERR"
}

# Renvoie (echo) la raison d'exclusion d'un bind mount, rien si autorisé
bind_exclusion_reason() {
  local s="${1%/}"
  [[ -z "$s" ]] && { echo "racine de l'hôte (/)"; return; }
  case "$s" in
    /proc|/proc/*|/sys|/sys/*|/dev|/dev/*) echo "pseudo-filesystem ($s)"; return ;;
    */docker.sock|*/containerd.sock|*/podman.sock) echo "socket de runtime ($s)"; return ;;
  esac
  rhost test -S "$s" && { echo "socket"; return; }
  rhost test -b "$s" -o -c "$s" && { echo "périphérique"; return; }
  rhost test -p "$s" && { echo "FIFO"; return; }
  if [[ -n "$DOCKER_ROOT" && ( "$s" == "${DOCKER_ROOT%/}" || "$s" == "${DOCKER_ROOT%/}/"* || "${DOCKER_ROOT%/}/" == "$s/"* ) ]]; then
    echo "DockerRootDir ($DOCKER_ROOT)"; return
  fi
  [[ -z "$REMOTE" && "$OUTDIR/" == "$s/"* ]] && { echo "contient le dossier de sortie (copie récursive)"; return; }
}

# copy_mount <source> <dossier_dest> <label> <état_conteneur>
copy_mount() {
  local src="$1" dest="$2" label="$3" state="$4" size rc
  mkdir -p "$dest"
  if ! rhost test -e "$src" 2>>"$ERR"; then
    warn "$label : source absente ou non locale ($src)"
    echo "status: missing" > "$dest/_meta.txt"; return
  fi
  size="$(rhost du -sb --one-file-system "$src" 2>>"$ERR" | cut -f1)"; size="${size:-0}"
  {
    echo "label:      $label"
    echo "source:     $src"
    echo "size_bytes: $size ($(human "$size"))"
    echo "container:  $state"
    echo "listed_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } > "$dest/_meta.txt"

  # Listing MAC times AVANT lecture (tar peut modifier les atime)
  {
    echo "mode|uid|gid|size|atime_epoch|mtime_epoch|ctime_epoch|type|path"
    rhost find "$src" -xdev -printf '%m|%U|%G|%s|%A@|%T@|%C@|%y|%p\n' 2>>"$ERR"
  } > "$dest/listing_mac.psv"

  if (( MAX_BYTES > 0 && size > MAX_BYTES )); then
    warn "$label : $(human "$size") > limite $(human "$MAX_BYTES") — contenu NON copié (listing conservé). Relancer avec --max-volume-size."
    echo "status:     skipped_size_limit" >> "$dest/_meta.txt"; return
  fi
  [[ "$state" == "running" ]] && warn "$label : copie à chaud (conteneur actif) — cohérence non garantie (bases de données !)"

  log "    copie $label ($(human "$size"))"
  printf '[%s] CMD: rhost tar %s -C %s -cf - > content.tar\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${TAR_OPTS[*]}" "$src" >> "$LOG"
  if rhost test -d "$src"; then
    rhost tar "${TAR_OPTS[@]}" -C "$src" -cf - . > "$dest/content.tar" 2>>"$ERR"; rc=$?
  else
    rhost tar "${TAR_OPTS[@]}" -C "$(dirname "$src")" -cf - "$(basename "$src")" > "$dest/content.tar" 2>>"$ERR"; rc=$?
  fi
  case $rc in
    0) echo "status:     copied" >> "$dest/_meta.txt" ;;
    1) warn "$label : fichiers modifiés pendant la copie (tar rc=1)"
       echo "status:     copied_with_changes" >> "$dest/_meta.txt" ;;
    *) warn "$label : échec tar (rc=$rc)"
       echo "status:     tar_failed_rc_$rc" >> "$dest/_meta.txt" ;;
  esac
}

[[ "$TARGET_UID" != "0" ]] && warn "Collecte sans root sur la cible (uid ${TARGET_UID:-?}) : fichiers de l'hôte, logs bruts et volumes probablement illisibles."

log "=== Début collecte docker-collect.sh v${VERSION} ==="
log "Hôte: $HOST | Case: ${CASE_ID:-n/a} | Analyste: ${ANALYST:-n/a} | Utilisateur: $(id -un) (uid $EUID)"
if [[ -n "$REMOTE" ]]; then
  log "Mode : DISTANT via SSH ($REMOTE) | élévation : ${SUDO[*]:-aucune} | collecteur : $(hostname 2>/dev/null)"
else
  log "Mode : LOCAL"
fi
log "Sortie: $OUTDIR"
[[ $VOLUMES -eq 1 ]] && log "Volumes : ON | binds : $([[ $INCLUDE_BINDS -eq 1 ]] && echo ON || echo OFF) | limite/montage : $([[ $MAX_BYTES -eq 0 ]] && echo illimitée || human "$MAX_BYTES")"

# ---- 1. État de l'hôte (volatil d'abord) et artefacts système --------------
H="$OUTDIR/host"
if [[ $HOST_ARTIFACTS -eq 1 ]]; then
  log "[1/7] État de l'hôte et artefacts système"
  mkdir -p "$H/live" "$H/journal" "$H/persistence"

  # 1a. Volatil : processus, réseau, sessions — en premier
  capture "$H/live/date_utc.txt"        rhost date -u '+%Y-%m-%dT%H:%M:%S.%NZ'
  capture "$H/live/uptime.txt"          rhost uptime
  capture "$H/live/ps_auxwwf.txt"       rhost ps auxwwf
  capture "$H/live/ps_lstart.txt"       rhost ps -eo pid,ppid,user,lstart,etime,args --sort=pid
  capture "$H/live/ss_tunap.txt"        rhost ss -tunap \
    || capture "$H/live/netstat_tunap.txt" rhost netstat -tunap
  capture "$H/live/ss_listen.txt"       rhost ss -tulpn
  capture "$H/live/ss_unix.txt"         rhost ss -xap
  capture "$H/live/ip_addr.txt"         rhost ip a \
    || capture "$H/live/ifconfig.txt"   rhost ifconfig -a
  capture "$H/live/ip_route.txt"        rhost ip route show table all
  capture "$H/live/ip_neigh.txt"        rhost ip neigh
  capture "$H/live/iptables-save.txt"   rhost iptables-save
  capture "$H/live/ip6tables-save.txt"  rhost ip6tables-save
  capture "$H/live/nft_ruleset.txt"     rhost nft list ruleset
  capture "$H/live/w.txt"               rhost w
  capture "$H/live/who.txt"             rhost who -a
  capture "$H/live/last.txt"            rhost last -Faiwx
  capture "$H/live/lastb.txt"           rhost lastb -Faiw
  capture "$H/live/lsmod.txt"           rhost lsmod
  capture "$H/live/mount.txt"           rhost mount
  capture "$H/live/df.txt"              rhost df -h

  # 1b. Journaux des services (daemon docker, containerd, ssh)
  JARGS=(--no-pager -o short-iso-precise)
  [[ -n "$JOURNAL_SINCE" ]] && JARGS+=(--since "$JOURNAL_SINCE")
  capture "$H/journal/journal_docker_containerd.txt" rhost journalctl "${JARGS[@]}" -u docker -u docker.socket -u containerd
  capture "$H/journal/journal_ssh.txt"               rhost journalctl "${JARGS[@]}" -u ssh -u sshd
  capture "$H/journal/journal_boots.txt"             rhost journalctl --no-pager --list-boots

  # 1c. Persistance (vues systemd + groupe docker)
  capture "$H/persistence/systemctl_units.txt"      rhost systemctl list-units --all --no-pager
  capture "$H/persistence/systemctl_unit_files.txt" rhost systemctl list-unit-files --no-pager
  capture "$H/persistence/systemctl_timers.txt"     rhost systemctl list-timers --all --no-pager
  capture "$H/persistence/docker_group.txt"         rhost getent group docker

  # 1d. Fichiers : logs d'authentification, comptes, historiques, clés SSH, cron, systemd
  FILES=(
    etc/passwd etc/group etc/sudoers etc/sudoers.d
    etc/crontab etc/cron.d etc/cron.hourly etc/cron.daily etc/cron.weekly etc/cron.monthly
    var/spool/cron etc/anacrontab
    etc/systemd/system etc/rc.local etc/ld.so.preload etc/profile.d
    etc/ssh/sshd_config etc/ssh/sshd_config.d
    etc/docker etc/hosts etc/resolv.conf etc/os-release
  )
  mapfile -t _logs < <(rhost find /var/log -maxdepth 1 -type f \( -name 'auth.log*' -o -name 'secure*' \) 2>>"$ERR")
  for f in "${_logs[@]}"; do FILES+=("${f#/}"); done
  # Historiques shell et clés SSH de tous les comptes ayant un home
  mapfile -t _homes < <(rhost cat /etc/passwd 2>>"$ERR" | cut -d: -f6 | sort -u | grep '^/.' | grep -vE '^/(proc|sys|dev|bin|sbin|usr/sbin)$')
  for hd in "${_homes[@]}"; do
    rhost test -d "$hd" 2>/dev/null || continue
    mapfile -t _uf < <(rhost find "$hd" -maxdepth 2 -xdev -type f \( -name '.*history' -o -path "$hd/.ssh/*" \) 2>>"$ERR")
    for f in "${_uf[@]}"; do FILES+=("${f#/}"); done
  done
  log "  copie de ${#FILES[@]} chemins système -> host/fs/"
  fetch / "$H/fs" "${FILES[@]}" || warn "copie partielle des fichiers système (voir errors.log)"
  # Liste avec dates de ce qui a été récupéré
  ( cd "$H/fs" 2>/dev/null && find . -printf '%TY-%Tm-%Td %TH:%TM:%TS %m %s %p\n' | sort -k5 ) > "$H/fs_listing.txt"
else
  log "[1/7] État de l'hôte : ignoré (--no-host)"
fi

# ---- 2. Contexte Docker -----------------------------------------------------
log "[2/7] Contexte hôte et daemon Docker"
{
  echo "case_id:      ${CASE_ID:-}"
  echo "analyst:      ${ANALYST:-}"
  echo "hostname:     $HOST"
  echo "mode:         $([[ -n "$REMOTE" ]] && echo "remote ssh ($REMOTE)" || echo local)"
  if [[ -n "$REMOTE" ]]; then
    echo "collector_host: $(hostname 2>/dev/null) ($(id -un))"
    echo "collector_utc:  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "target_utc:     $(rhost date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)"
  fi
  echo "start_utc:    $START_UTC"
  echo "local_time:   $(rhost date)"
  echo "timezone:     $(rhost date +%Z) ($(rhost date +%z))"
  echo "kernel:       $(rhost uname -a)"
  echo "collector:    $(rhost id)"
  echo "docker_root:  $DOCKER_ROOT"
  echo "tar_opts:     ${TAR_OPTS[*]}"
} > "$OUTDIR/host/collection_info.txt"
rhost cat /etc/os-release > "$OUTDIR/host/os-release.txt" 2>>"$ERR" || rm -f "$OUTDIR/host/os-release.txt"
capture "$OUTDIR/host/docker_version.txt"      rdocker version
capture "$OUTDIR/host/docker_info.txt"         rdocker info
capture "$OUTDIR/host/docker_ps_all.txt"       rdocker ps -a --no-trunc --size
capture "$OUTDIR/host/docker_ps_all.json"      rdocker ps -a --no-trunc --format '{{json .}}'
capture "$OUTDIR/host/docker_images.txt"       rdocker images -a --digests --no-trunc
capture "$OUTDIR/host/docker_networks.txt"     rdocker network ls --no-trunc
capture "$OUTDIR/host/docker_volumes.txt"      rdocker volume ls
capture "$OUTDIR/host/docker_system_df.txt"    rdocker system df -v
if rhost test -r /etc/docker/daemon.json 2>/dev/null; then
  rhost cat /etc/docker/daemon.json > "$OUTDIR/host/daemon.json" 2>>"$ERR"
fi

# Inspect de tous les réseaux / volumes (utile pour la corrélation)
mapfile -t _nets < <(rdocker network ls -q 2>>"$ERR")
(( ${#_nets[@]} )) && rdocker network inspect "${_nets[@]}" > "$OUTDIR/host/networks_inspect.json" 2>>"$ERR"
mapfile -t _vols < <(rdocker volume ls -q 2>>"$ERR")
(( ${#_vols[@]} )) && rdocker volume inspect "${_vols[@]}" > "$OUTDIR/host/volumes_inspect.json" 2>>"$ERR"

if [[ $EVENTS -eq 1 ]]; then
  now="$(rhost date +%s 2>/dev/null)"; now="${now:-$(date +%s)}"; from=$(( now - EVENTS_DAYS * 86400 ))
  capture "$OUTDIR/host/docker_events.jsonl" rdocker events --since "$from" --until "$now" --format '{{json .}}'
fi

# ---- 3. Résolution des conteneurs ------------------------------------------
log "[3/7] Résolution des conteneurs"
declare -a TARGETS=()
if [[ ${#CONTAINERS_IN[@]} -eq 0 ]]; then
  mapfile -t TARGETS < <(rdocker ps -aq --no-trunc)
  log "Mode : tous les conteneurs (${#TARGETS[@]})"
else
  declare -A seen=()
  for c in "${CONTAINERS_IN[@]}"; do
    full="$(rdocker inspect -f '{{.Id}}' "$c" 2>/dev/null)"
    if [[ -z "$full" ]]; then warn "conteneur introuvable : $c"; continue; fi
    [[ -n "${seen[$full]:-}" ]] && continue
    seen[$full]=1; TARGETS+=("$full")
  done
  log "Mode : sélection (${#TARGETS[@]}/${#CONTAINERS_IN[@]} résolus)"
fi
[[ ${#TARGETS[@]} -eq 0 ]] && warn "Aucun conteneur à collecter."
printf '%s\n' "${TARGETS[@]}" > "$OUTDIR/host/target_containers.txt"

# ---- 4. Collecte par conteneur ---------------------------------------------
log "[4/7] Collecte par conteneur"
declare -A IMAGES=()
declare -A CSTATE=()
LOG_ARGS=(-t --details)
[[ -n "$SINCE" ]] && LOG_ARGS+=(--since "$SINCE")
[[ -n "$UNTIL" ]] && LOG_ARGS+=(--until "$UNTIL")

i=0
for cid in "${TARGETS[@]}"; do
  i=$((i+1))
  # Une seule requête pour les champs de base
  IFS='|' read -r name state driver img logpath < <(rdocker inspect -f '{{.Name}}|{{.State.Status}}|{{.HostConfig.LogConfig.Type}}|{{.Image}}|{{.LogPath}}' "$cid" 2>/dev/null)
  name="${name#/}"
  d="$OUTDIR/containers/${cid:0:12}_$(safe_name "$name")"
  mkdir -p "$d"
  CSTATE[$cid]="$state"
  log "  ($i/${#TARGETS[@]}) ${cid:0:12} [$name] état=$state log-driver=$driver"

  [[ -n "$img" ]] && IMAGES[$img]=1

  capture "$d/inspect.json" rdocker inspect "$cid"
  capture "$d/diff.txt"     rdocker diff "$cid"      # fichiers A/C/D vs image
  capture "$d/port.txt"     rdocker port "$cid"
  rdocker inspect -f '{{range .Mounts}}{{.Type}}|{{.Name}}|{{.Source}}|{{.Destination}}|{{.RW}}{{println}}{{end}}' "$cid" 2>>"$ERR" \
    | sed '/^$/d' > "$d/mounts.psv"
  if [[ "$state" == "running" ]]; then
    capture "$d/top.txt"    rdocker top "$cid" -eo pid,ppid,user,lstart,etime,cmd \
      || capture "$d/top.txt" rdocker top "$cid"
    capture "$d/stats.txt"  rdocker stats --no-stream --no-trunc "$cid"
  fi

  # Logs via l'API (stdout et stderr séparés, horodatés)
  printf '[%s] CMD: rdocker logs %s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${LOG_ARGS[*]}" "$cid" >> "$LOG"
  if ! rdocker logs "${LOG_ARGS[@]}" "$cid" > "$d/stdout.log" 2> "$d/stderr.log"; then
    warn "docker logs a échoué pour ${cid:0:12} (driver '$driver' non lisible ?) — voir $d/stderr.log"
  fi

  # Logs bruts du daemon (json-file / local), y compris rotations
  if [[ $RAW_LOGS -eq 1 ]]; then
    if [[ -n "$logpath" ]]; then
      logdir="$(dirname "$logpath")"; logbase="$(basename "$logpath")"
      mapfile -t lf < <(rhost find "$logdir" -maxdepth 1 -name "${logbase}*" -printf '%f\n' 2>>"$ERR")
      if (( ${#lf[@]} )); then
        fetch "$logdir" "$d/raw_logs" "${lf[@]}" || warn "copie brute partielle : $logpath"
        rhost ls -la --time-style=full-iso "${lf[@]/#/$logdir/}" > "$d/raw_logs/_listing.txt" 2>>"$ERR"
      else
        warn "logs bruts inaccessibles : $logpath"
      fi
    elif [[ "$driver" == "local" ]]; then
      cdir="${DOCKER_ROOT}/containers/$cid"
      rhost test -d "$cdir/local-logs" 2>/dev/null && fetch "$cdir" "$d/raw_logs" local-logs
    fi
  fi

  # Export filesystem (optionnel)
  if [[ $EXPORT_FS -eq 1 ]]; then
    log "    export filesystem -> fs_export.tar"
    capture "$d/fs_export.tar" rdocker export "$cid"
  fi
done

# ---- 5. Volumes et bind mounts (optionnel) ---------------------------------
declare -A VOLS_DONE=()
NB_VOLS=0; NB_BINDS=0
if [[ $VOLUMES -eq 1 ]]; then
  log "[5/7] Volumes et montages"
  for cid in "${TARGETS[@]}"; do
    d="$(ls -d "$OUTDIR/containers/${cid:0:12}_"* 2>/dev/null | head -1)"
    [[ -s "$d/mounts.psv" ]] || continue
    state="${CSTATE[$cid]:-unknown}"
    log "  ${cid:0:12} ($(wc -l < "$d/mounts.psv") montage(s))"
    # fd 3 : évite que docker/tar/find/ssh consomment la liste via stdin
    while IFS='|' read -r mtype mname msrc mdst mrw <&3; do
      case "$mtype" in
        volume)
          if [[ -n "${VOLS_DONE[$mname]:-}" ]]; then
            log "    volume $mname -> $mdst : déjà collecté (partagé)"; continue
          fi
          VOLS_DONE[$mname]=1
          vdir="$OUTDIR/volumes/$(safe_name "$mname")"
          mkdir -p "$vdir"
          capture "$vdir/volume_inspect.json" rdocker volume inspect "$mname"
          echo "${cid}|${mdst}|rw=${mrw}" >> "$vdir/used_by.psv"
          copy_mount "$msrc" "$vdir" "volume $mname" "$state"
          NB_VOLS=$((NB_VOLS+1)) ;;
        bind)
          if [[ $INCLUDE_BINDS -ne 1 ]]; then
            log "    bind $msrc -> $mdst : ignoré (ajouter --include-binds)"; continue
          fi
          reason="$(bind_exclusion_reason "$msrc")"
          if [[ -n "$reason" ]]; then
            warn "bind $msrc -> $mdst exclu : $reason"; continue
          fi
          bdir="$d/binds/$(safe_name "${mdst#/}")"
          copy_mount "$msrc" "$bdir" "bind $msrc" "$state"
          echo "destination: $mdst (rw=$mrw)" >> "$bdir/_meta.txt"
          NB_BINDS=$((NB_BINDS+1)) ;;
        *)
          log "    montage $mtype -> $mdst : ignoré (type non copiable)" ;;
      esac
    done 3< "$d/mounts.psv"
  done
else
  log "[5/7] Volumes : ignorés (utiliser --volumes)"
fi

# ---- 6. Sauvegarde des images ----------------------------------------------
if [[ $SAVE_IMAGES -eq 1 && ${#IMAGES[@]} -gt 0 ]]; then
  log "[6/7] Sauvegarde de ${#IMAGES[@]} image(s)"
  for img in "${!IMAGES[@]}"; do
    short="${img#sha256:}"; short="${short:0:12}"
    idir="$OUTDIR/images/$short"; mkdir -p "$idir"
    capture "$idir/image_inspect.json" rdocker image inspect "$img"
    capture "$idir/history.txt"        rdocker history --no-trunc "$img"
    mapfile -t tags < <(rdocker image inspect -f '{{range .RepoTags}}{{println .}}{{end}}' "$img" 2>/dev/null | sed '/^$/d')
    # docker save vers stdout : l'archive est écrite localement (rien sur la cible)
    if [[ ${#tags[@]} -gt 0 ]]; then
      log "  $short (${tags[*]})"
      capture "$idir/image.tar" rdocker save "${tags[@]}"
    else
      log "  $short (sans tag — sauvegarde par ID)"
      capture "$idir/image.tar" rdocker save "$img"
    fi
  done
else
  log "[6/7] Sauvegarde des images : ignorée"
fi

# ---- 7. Intégrité + archive -------------------------------------------------
log "[7/7] Calcul des empreintes SHA256"
END_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "end_utc:      $END_UTC" >> "$OUTDIR/host/collection_info.txt"
log "=== Fin collecte ($END_UTC) ==="

( cd "$OUTDIR" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS )

if [[ $ARCHIVE -eq 1 ]]; then
  base="$(basename "$OUTDIR")"; parent="$(dirname "$OUTDIR")"
  tar -C "$parent" -czf "$parent/${base}.tar.gz" "$base" 2>>"$ERR" \
    && ( cd "$parent" && sha256sum "${base}.tar.gz" > "${base}.tar.gz.sha256" ) \
    && echo -e "\nArchive : $parent/${base}.tar.gz\nSHA256  : $(cut -d' ' -f1 "$parent/${base}.tar.gz.sha256")" >&2
fi

nerr=$(grep -c . "$ERR" 2>/dev/null || true)
echo -e "Dossier : $OUTDIR\nConteneurs : ${#TARGETS[@]} | Images : ${#IMAGES[@]} | Volumes : $NB_VOLS | Binds : $NB_BINDS | Lignes d'erreur : ${nerr:-0}" >&2
