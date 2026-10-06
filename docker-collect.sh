#!/usr/bin/env bash
# =============================================================================
#  docker-collect.sh — Collecte forensique d'un hôte Docker
#  - Logs de tous les conteneurs (via docker logs + fichiers bruts du daemon)
#  - Métadonnées (inspect, diff, top, ports, réseaux, volumes, events)
#  - Sauvegarde des images utilisées (docker save) pour export
#  - Export optionnel du filesystem des conteneurs (docker export)
#  - Copie optionnelle des volumes nommés / bind mounts (avec garde-fous)
#  - Journal de collecte horodaté UTC + SHA256 de chaque fichier + archive
#
#  Principe : lecture seule côté Docker. Aucun "docker commit", aucun
#  stop/restart, aucune modification des conteneurs.
# =============================================================================
set -uo pipefail

VERSION="1.1"
DOCKER="${DOCKER_BIN:-docker}"

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

usage() {
cat <<EOF
docker-collect.sh v${VERSION} — collecte forensique Docker

Usage : sudo $0 [options]

Sélection des conteneurs (défaut : TOUS, running + stopped)
  -c, --container ID[,ID...]  ID(s) ou nom(s) de conteneur. Répétable.
  -f, --file FICHIER          Fichier contenant un ID/nom par ligne (# = commentaire)
  -l, --list                  Liste les conteneurs présents puis quitte

Sortie / dossier
  -o, --output DIR            Dossier de sortie (défaut : ./docker-evidence_<host>_<date>)
      --case ID               Référence du dossier d'investigation
      --analyst NOM           Nom de l'analyste (chaîne de traçabilité)

Options de collecte
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

Exemples
  sudo $0                                   # tout collecter
  sudo $0 -c a1b2c3,web_nginx --export-fs   # 2 conteneurs + filesystem
  sudo $0 -c web --volumes --include-binds --max-volume-size 5G
  sudo $0 -f suspects.txt --case INC-2026-042 --analyst H13ris
  sudo $0 --no-images --since 72h           # logs des 72 dernières heures
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

# ---- Pré-requis -------------------------------------------------------------
command -v "$DOCKER" >/dev/null 2>&1 || { echo "Erreur : docker introuvable" >&2; exit 1; }
"$DOCKER" info >/dev/null 2>&1 || { echo "Erreur : impossible de joindre le daemon Docker (droits ? socket ?)" >&2; exit 1; }
command -v sha256sum >/dev/null 2>&1 || { echo "Erreur : sha256sum introuvable" >&2; exit 1; }

if [[ $LIST_ONLY -eq 1 ]]; then
  "$DOCKER" ps -a --no-trunc --format 'table {{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.CreatedAt}}'
  exit 0
fi

DOCKER_ROOT="$("$DOCKER" info -f '{{.DockerRootDir}}' 2>/dev/null)"

# Options tar : préserver propriétaires numériques, xattrs, ACL ; ne pas traverser les FS
TAR_OPTS=(--numeric-owner --one-file-system)
if tar --help 2>/dev/null | grep -q -- '--xattrs'; then TAR_OPTS+=(--xattrs --xattrs-include='*'); fi
if tar --help 2>/dev/null | grep -q -- '--acls';   then TAR_OPTS+=(--acls); fi

HOST="$(hostname 2>/dev/null || echo unknown)"
START_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
[[ -z "$OUTDIR" ]] && OUTDIR="./docker-evidence_${HOST}_${STAMP}"

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

# Renvoie (echo) la raison d'exclusion d'un bind mount, rien si autorisé
bind_exclusion_reason() {
  local s="${1%/}"
  [[ -z "$s" ]] && { echo "racine de l'hôte (/)"; return; }
  case "$s" in
    /proc|/proc/*|/sys|/sys/*|/dev|/dev/*) echo "pseudo-filesystem ($s)"; return ;;
    */docker.sock|*/containerd.sock|*/podman.sock) echo "socket de runtime ($s)"; return ;;
  esac
  [[ -S "$s" ]] && { echo "socket"; return; }
  [[ -b "$s" || -c "$s" ]] && { echo "périphérique"; return; }
  [[ -p "$s" ]] && { echo "FIFO"; return; }
  if [[ -n "$DOCKER_ROOT" && ( "$s" == "${DOCKER_ROOT%/}" || "$s" == "${DOCKER_ROOT%/}/"* || "${DOCKER_ROOT%/}/" == "$s/"* ) ]]; then
    echo "DockerRootDir ($DOCKER_ROOT)"; return
  fi
  [[ "$OUTDIR/" == "$s/"* ]] && { echo "contient le dossier de sortie (copie récursive)"; return; }
}

# copy_mount <source> <dossier_dest> <label> <état_conteneur>
copy_mount() {
  local src="$1" dest="$2" label="$3" state="$4" size rc
  mkdir -p "$dest"
  if [[ ! -e "$src" ]]; then
    warn "$label : source absente ou non locale ($src)"
    echo "status: missing" > "$dest/_meta.txt"; return
  fi
  size="$(du -sb --one-file-system "$src" 2>>"$ERR" | cut -f1)"; size="${size:-0}"
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
    find "$src" -xdev -printf '%m|%U|%G|%s|%A@|%T@|%C@|%y|%p\n' 2>>"$ERR"
  } > "$dest/listing_mac.psv"

  if (( MAX_BYTES > 0 && size > MAX_BYTES )); then
    warn "$label : $(human "$size") > limite $(human "$MAX_BYTES") — contenu NON copié (listing conservé). Relancer avec --max-volume-size."
    echo "status:     skipped_size_limit" >> "$dest/_meta.txt"; return
  fi
  [[ "$state" == "running" ]] && warn "$label : copie à chaud (conteneur actif) — cohérence non garantie (bases de données !)"

  log "    copie $label ($(human "$size"))"
  printf '[%s] CMD: tar %s -C %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${TAR_OPTS[*]}" "$src" >> "$LOG"
  if [[ -d "$src" ]]; then
    tar "${TAR_OPTS[@]}" -C "$src" -cf "$dest/content.tar" . 2>>"$ERR"; rc=$?
  else
    tar "${TAR_OPTS[@]}" -C "$(dirname "$src")" -cf "$dest/content.tar" "$(basename "$src")" 2>>"$ERR"; rc=$?
  fi
  case $rc in
    0) echo "status:     copied" >> "$dest/_meta.txt" ;;
    1) warn "$label : fichiers modifiés pendant la copie (tar rc=1)"
       echo "status:     copied_with_changes" >> "$dest/_meta.txt" ;;
    *) warn "$label : échec tar (rc=$rc)"
       echo "status:     tar_failed_rc_$rc" >> "$dest/_meta.txt" ;;
  esac
}

[[ $EUID -ne 0 ]] && warn "Non-root : la copie des logs bruts et des volumes (/var/lib/docker) échouera probablement."

log "=== Début collecte docker-collect.sh v${VERSION} ==="
log "Hôte: $HOST | Case: ${CASE_ID:-n/a} | Analyste: ${ANALYST:-n/a} | Utilisateur: $(id -un) (uid $EUID)"
log "Sortie: $OUTDIR"
[[ $VOLUMES -eq 1 ]] && log "Volumes : ON | binds : $([[ $INCLUDE_BINDS -eq 1 ]] && echo ON || echo OFF) | limite/montage : $([[ $MAX_BYTES -eq 0 ]] && echo illimitée || human "$MAX_BYTES")"

# ---- 1. Contexte hôte -------------------------------------------------------
log "[1/6] Contexte hôte et daemon"
{
  echo "case_id:      ${CASE_ID:-}"
  echo "analyst:      ${ANALYST:-}"
  echo "hostname:     $HOST"
  echo "start_utc:    $START_UTC"
  echo "local_time:   $(date)"
  echo "timezone:     $(date +%Z) ($(date +%z))"
  echo "kernel:       $(uname -a)"
  echo "collector:    $(id)"
  echo "docker_root:  $DOCKER_ROOT"
  echo "tar_opts:     ${TAR_OPTS[*]}"
} > "$OUTDIR/host/collection_info.txt"
[[ -r /etc/os-release ]] && cp /etc/os-release "$OUTDIR/host/os-release.txt"
capture "$OUTDIR/host/docker_version.txt"      "$DOCKER" version
capture "$OUTDIR/host/docker_info.txt"         "$DOCKER" info
capture "$OUTDIR/host/docker_ps_all.txt"       "$DOCKER" ps -a --no-trunc --size
capture "$OUTDIR/host/docker_ps_all.json"      "$DOCKER" ps -a --no-trunc --format '{{json .}}'
capture "$OUTDIR/host/docker_images.txt"       "$DOCKER" images -a --digests --no-trunc
capture "$OUTDIR/host/docker_networks.txt"     "$DOCKER" network ls --no-trunc
capture "$OUTDIR/host/docker_volumes.txt"      "$DOCKER" volume ls
capture "$OUTDIR/host/docker_system_df.txt"    "$DOCKER" system df -v
[[ -r /etc/docker/daemon.json ]] && cp -p /etc/docker/daemon.json "$OUTDIR/host/daemon.json"

# Inspect de tous les réseaux / volumes (utile pour la corrélation)
"$DOCKER" network ls -q 2>/dev/null | xargs -r "$DOCKER" network inspect > "$OUTDIR/host/networks_inspect.json" 2>>"$ERR"
"$DOCKER" volume ls -q 2>/dev/null  | xargs -r "$DOCKER" volume inspect  > "$OUTDIR/host/volumes_inspect.json"  2>>"$ERR"

if [[ $EVENTS -eq 1 ]]; then
  now=$(date +%s); from=$(( now - EVENTS_DAYS * 86400 ))
  capture "$OUTDIR/host/docker_events.jsonl" "$DOCKER" events --since "$from" --until "$now" --format '{{json .}}'
fi

# ---- 2. Résolution des conteneurs ------------------------------------------
log "[2/6] Résolution des conteneurs"
declare -a TARGETS=()
if [[ ${#CONTAINERS_IN[@]} -eq 0 ]]; then
  mapfile -t TARGETS < <("$DOCKER" ps -aq --no-trunc)
  log "Mode : tous les conteneurs (${#TARGETS[@]})"
else
  declare -A seen=()
  for c in "${CONTAINERS_IN[@]}"; do
    full="$("$DOCKER" inspect -f '{{.Id}}' "$c" 2>/dev/null)"
    if [[ -z "$full" ]]; then warn "conteneur introuvable : $c"; continue; fi
    [[ -n "${seen[$full]:-}" ]] && continue
    seen[$full]=1; TARGETS+=("$full")
  done
  log "Mode : sélection (${#TARGETS[@]}/${#CONTAINERS_IN[@]} résolus)"
fi
[[ ${#TARGETS[@]} -eq 0 ]] && warn "Aucun conteneur à collecter."
printf '%s\n' "${TARGETS[@]}" > "$OUTDIR/host/target_containers.txt"

# ---- 3. Collecte par conteneur ---------------------------------------------
log "[3/6] Collecte par conteneur"
declare -A IMAGES=()
declare -A CSTATE=()
LOG_ARGS=(-t --details)
[[ -n "$SINCE" ]] && LOG_ARGS+=(--since "$SINCE")
[[ -n "$UNTIL" ]] && LOG_ARGS+=(--until "$UNTIL")

i=0
for cid in "${TARGETS[@]}"; do
  i=$((i+1))
  name="$("$DOCKER" inspect -f '{{.Name}}' "$cid" 2>/dev/null)"; name="${name#/}"
  state="$("$DOCKER" inspect -f '{{.State.Status}}' "$cid" 2>/dev/null)"
  driver="$("$DOCKER" inspect -f '{{.HostConfig.LogConfig.Type}}' "$cid" 2>/dev/null)"
  img="$("$DOCKER" inspect -f '{{.Image}}' "$cid" 2>/dev/null)"
  d="$OUTDIR/containers/${cid:0:12}_$(safe_name "$name")"
  mkdir -p "$d"
  CSTATE[$cid]="$state"
  log "  ($i/${#TARGETS[@]}) ${cid:0:12} [$name] état=$state log-driver=$driver"

  [[ -n "$img" ]] && IMAGES[$img]=1

  capture "$d/inspect.json" "$DOCKER" inspect "$cid"
  capture "$d/diff.txt"     "$DOCKER" diff "$cid"      # fichiers A/C/D vs image
  capture "$d/port.txt"     "$DOCKER" port "$cid"
  "$DOCKER" inspect -f '{{range .Mounts}}{{.Type}}|{{.Name}}|{{.Source}}|{{.Destination}}|{{.RW}}{{println}}{{end}}' "$cid" 2>>"$ERR" \
    | sed '/^$/d' > "$d/mounts.psv"
  if [[ "$state" == "running" ]]; then
    capture "$d/top.txt"    "$DOCKER" top "$cid" -eo pid,ppid,user,lstart,etime,cmd \
      || capture "$d/top.txt" "$DOCKER" top "$cid"
    capture "$d/stats.txt"  "$DOCKER" stats --no-stream --no-trunc "$cid"
  fi

  # Logs via l'API (stdout et stderr séparés, horodatés)
  printf '[%s] CMD: %s logs %s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$DOCKER" "${LOG_ARGS[*]}" "$cid" >> "$LOG"
  if ! "$DOCKER" logs "${LOG_ARGS[@]}" "$cid" > "$d/stdout.log" 2> "$d/stderr.log"; then
    warn "docker logs a échoué pour ${cid:0:12} (driver '$driver' non lisible ?) — voir $d/stderr.log"
  fi

  # Logs bruts du daemon (json-file / local), y compris rotations
  if [[ $RAW_LOGS -eq 1 ]]; then
    logpath="$("$DOCKER" inspect -f '{{.LogPath}}' "$cid" 2>/dev/null)"
    if [[ -n "$logpath" ]]; then
      mkdir -p "$d/raw_logs"
      if ls "$logpath"* >/dev/null 2>>"$ERR"; then
        cp -p "$logpath"* "$d/raw_logs/" 2>>"$ERR" || warn "copie brute partielle : $logpath"
        ls -la --time-style=full-iso "$logpath"* > "$d/raw_logs/_listing.txt" 2>>"$ERR"
      else
        warn "logs bruts inaccessibles : $logpath"
      fi
    elif [[ "$driver" == "local" ]]; then
      cdir="${DOCKER_ROOT}/containers/$cid/local-logs"
      [[ -d "$cdir" ]] && cp -rp "$cdir" "$d/raw_logs" 2>>"$ERR"
    fi
  fi

  # Export filesystem (optionnel)
  if [[ $EXPORT_FS -eq 1 ]]; then
    log "    export filesystem -> fs_export.tar"
    capture "$d/fs_export.tar" "$DOCKER" export "$cid"
  fi
done

# ---- 4. Volumes et bind mounts (optionnel) ---------------------------------
declare -A VOLS_DONE=()
NB_VOLS=0; NB_BINDS=0
if [[ $VOLUMES -eq 1 ]]; then
  log "[4/6] Volumes et montages"
  for cid in "${TARGETS[@]}"; do
    d="$(ls -d "$OUTDIR/containers/${cid:0:12}_"* 2>/dev/null | head -1)"
    [[ -s "$d/mounts.psv" ]] || continue
    state="${CSTATE[$cid]:-unknown}"
    log "  ${cid:0:12} ($(wc -l < "$d/mounts.psv") montage(s))"
    # fd 3 : évite que docker/tar/find consomment la liste via stdin
    while IFS='|' read -r mtype mname msrc mdst mrw <&3; do
      case "$mtype" in
        volume)
          if [[ -n "${VOLS_DONE[$mname]:-}" ]]; then
            log "    volume $mname -> $mdst : déjà collecté (partagé)"; continue
          fi
          VOLS_DONE[$mname]=1
          vdir="$OUTDIR/volumes/$(safe_name "$mname")"
          mkdir -p "$vdir"
          capture "$vdir/volume_inspect.json" "$DOCKER" volume inspect "$mname"
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
  log "[4/6] Volumes : ignorés (utiliser --volumes)"
fi

# ---- 5. Sauvegarde des images ----------------------------------------------
if [[ $SAVE_IMAGES -eq 1 && ${#IMAGES[@]} -gt 0 ]]; then
  log "[5/6] Sauvegarde de ${#IMAGES[@]} image(s)"
  for img in "${!IMAGES[@]}"; do
    short="${img#sha256:}"; short="${short:0:12}"
    idir="$OUTDIR/images/$short"; mkdir -p "$idir"
    capture "$idir/image_inspect.json" "$DOCKER" image inspect "$img"
    capture "$idir/history.txt"        "$DOCKER" history --no-trunc "$img"
    mapfile -t tags < <("$DOCKER" image inspect -f '{{range .RepoTags}}{{println .}}{{end}}' "$img" 2>/dev/null | sed '/^$/d')
    if [[ ${#tags[@]} -gt 0 ]]; then
      log "  $short (${tags[*]})"
      capture /dev/null "$DOCKER" save -o "$idir/image.tar" "${tags[@]}"
    else
      log "  $short (sans tag — sauvegarde par ID)"
      capture /dev/null "$DOCKER" save -o "$idir/image.tar" "$img"
    fi
  done
else
  log "[5/6] Sauvegarde des images : ignorée"
fi

# ---- 6. Intégrité + archive -------------------------------------------------
log "[6/6] Calcul des empreintes SHA256"
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
