"""Verify a downloaded Meshest connector against an independent release commit.

This standalone bootstrap must itself come from the trusted release publisher,
not from the coordinator archive it verifies. No credentials, account connection,
package installation, model work or automatic retry is performed.
"""
import argparse, hashlib, json, os, platform, re, stat, subprocess, sys, tarfile
import urllib.request
from pathlib import Path

PUBLISHER = 'https://raw.githubusercontent.com/Meshest/releases/'
PREPARATION = 'meshest-pilot/service/ops/private-pilot/package-connector.py'
LIMIT = 8192

def require(value, code):
    if not value: raise ValueError('setup_'+code)

def architecture():
    require(sys.platform == 'linux' and sys.version_info >= (3, 11), 'linux_python_required')
    require(os.geteuid() != 0, 'non_root_required')
    name = platform.machine().lower()
    require(name in ('aarch64', 'arm64', 'x86_64', 'amd64'), 'architecture_unsupported')
    return 'arm64' if name in ('aarch64', 'arm64') else 'x64'

def validate_record(value, arch):
    require(arch in ('arm64', 'x64'), 'release_record_invalid')
    require(isinstance(value, dict) and set(value) == {'profile', 'platform', 'architecture', 'filename', 'sha256', 'bytes', 'download_path', 'preparation'}, 'release_record_invalid')
    require(value['profile'] == 'meshest.connector-packet.0.1' and value['platform'] == 'linux' and
            value['architecture'] == arch and value['filename'] == 'meshest-pilot-linux-'+arch+'.tar.gz' and
            value['download_path'] == '/connector-packet', 'release_record_invalid')
    preparation = value['preparation']
    require(isinstance(preparation, dict) and set(preparation) == {'filename', 'bytes', 'sha256', 'download_path'} and
            preparation['filename'] == 'meshest-prepare.py' and preparation['download_path'] == '/connector-packet/prepare', 'release_record_invalid')
    for item, maximum in [(value, 512*1024*1024), (preparation, 65536)]:
        require(type(item['bytes']) is int and 0 < item['bytes'] <= maximum and isinstance(item['sha256'], str) and
                re.fullmatch('[a-f0-9]{64}', item['sha256']), 'release_record_invalid')
    return value

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError('setup_release_redirect_refused')

def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'release_record_invalid')
        result[key] = value
    return result

def release_record(commit, arch):
    require(isinstance(commit, str) and re.fullmatch('[a-f0-9]{40}', commit) and arch in ('arm64', 'x64'), 'release_commit_invalid')
    url = PUBLISHER+commit+'/connector-linux-'+arch+'.json'
    # No coordinator cookie, bearer header, ambient proxy or redirect is used.
    # HTTPS uses Python's standard certificate verification. This is publisher
    # TLS/immutable-commit trust, not a release signature or protection against
    # a compromised publisher or malicious instructions copied by the user.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    request = urllib.request.Request(url, headers={'Accept':'application/json'})
    with opener.open(request, timeout=10) as response:
        require(response.geturl() == url, 'release_redirect_refused')
        data = response.read(LIMIT+1)
    require(len(data) <= LIMIT, 'release_record_too_large')
    return validate_record(json.loads(data.decode('utf-8'), object_pairs_hook=unique_object), arch)

def fingerprint(meta):
    return tuple(getattr(meta, key) for key in ('st_dev', 'st_ino', 'st_size', 'st_mode', 'st_uid', 'st_nlink', 'st_mtime_ns', 'st_ctime_ns'))

def prepare(archive, destination, record, arch):
    validate_record(record, arch)
    require(archive.is_absolute() and destination.is_absolute() and '..' not in destination.parts, 'absolute_paths_required')
    require(not os.path.lexists(destination), 'destination_exists')
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    with os.fdopen(os.open(archive, flags), 'rb') as raw:
        before = os.fstat(raw.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid in (0, os.geteuid()) and
                not before.st_mode & 0o022 and before.st_size == record['bytes'], 'archive_invalid')
        require(hashlib.file_digest(raw, 'sha256').hexdigest() == record['sha256'], 'archive_digest_mismatch')
        raw.seek(0); helper = None; count = total = 0
        # Read one verified tool without extracting or executing archive content.
        # The canonical extractor still owns full path/mode/quota validation.
        with tarfile.open(fileobj=raw, mode='r|gz') as packet:
            for member in packet:
                count += 1; total += member.size
                require(count <= 4096 and 0 <= member.size <= 512*1024*1024 and total <= 4*1024**3, 'archive_inventory_limit')
                if member.name == PREPARATION:
                    require(helper is None and member.isfile() and member.size == record['preparation']['bytes'], 'preparation_invalid')
                    with packet.extractfile(member) as stream: helper = stream.read(65537)
        require(helper is not None and len(helper) == record['preparation']['bytes'] and
                hashlib.sha256(helper).hexdigest() == record['preparation']['sha256'], 'preparation_digest_mismatch')
        require(fingerprint(before) == fingerprint(os.fstat(raw.fileno())), 'archive_changed')
    # Feed only authenticated code to an isolated Python interpreter. No helper
    # tempfile or shell is used. The extractor reopens and rehashes the archive,
    # preserves existing/partial destinations and starts no agent work.
    subprocess.run([sys.executable, '-I', '-', 'extract', '--archive', str(archive),
                    '--archive-sha256', record['sha256'], '--destination', str(destination)],
                   input=helper, env={'PATH':os.defpath}, check=True, timeout=120)

def failure_message(error):
    code = str(error) if isinstance(error, ValueError) and re.fullmatch('setup_[a-z_]+', str(error)) else 'setup_unavailable'
    guidance = ''
    if code == 'setup_destination_exists':
        guidance = ' Keep the existing destination unchanged. For a separate installation, choose a new absolute destination that does not exist; do not delete or reuse saved state.'
    elif isinstance(error, subprocess.CalledProcessError):
        guidance = (' Authenticated preparation stopped; its diagnostic appears above.'
                    ' If it reports packet_extract_capacity_unavailable, check the effective VM/user disk quota and available capacity; shared filesystem free space alone does not establish quota capacity.'
                    ' If it reports packet_extract_destination_exists, keep that path unchanged and choose a new absent destination for a separate installation.'
                    ' Inspect any partial destination before deciding on a deliberate manual attempt; do not delete or reuse saved state.')
    return code+'; preserve downloaded files and any partial destination. No automatic retry.'+guidance+'\n'

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release', required=True, help='Immutable commit in the independent Meshest/releases publisher')
    parser.add_argument('--archive', required=True, type=Path)
    parser.add_argument('--destination', required=True, type=Path)
    args = parser.parse_args()
    try:
        require(sys.flags.isolated, 'isolated_python_required')
        arch = architecture()
        prepare(args.archive.absolute(), args.destination.absolute(), release_record(args.release, arch), arch)
    except (ValueError, OSError, tarfile.TarError, subprocess.SubprocessError) as error:
        parser.exit(1, failure_message(error))
