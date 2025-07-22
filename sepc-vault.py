from fastapi import FastAPI, Body
from pydantic import BaseModel
from fusepy import FUSE, FuseOSError, LoggingMixIn, Operations
from collections import defaultdict
from threading import Lock
import os
import errno
import threading
import re
import base64
import time
import imghdr
import math

def looks_like_media(raw: bytes) -> bool:
	magic_bytes = {
		b'\xFF\xD8\xFF': 'JPEG',
		b'\x89PNG': 'PNG',
		b'GIF87a': 'GIF',
		b'GIF89a': 'GIF',
		b'\x00\x00\x00\x18ftyp': 'MP4',
		b'RIFF': 'WEBM/AVI/WAV'
	}
	for magic, filetype in magic_bytes.items():
		if raw.startswith(magic):
			print(f"[!] Rejected upload: magic bytes detected for {filetype}")
			return True
	if imghdr.what(None, h=raw):
		print("[!] Rejected upload: image detected by imghdr")
		return True
	return False

def shannon_entropy(data: bytes) -> float:
	if not data:
		return 0.0
	freq = {b: data.count(b) for b in set(data)}
	return -sum((f / len(data)) * math.log2(f / len(data)) for f in freq.values())

def analyze_blob(decoded: bytes) -> dict:
	return {
		"is_media": looks_like_media(decoded),
		"entropy": shannon_entropy(decoded)
	}

def is_valid_pool(s):
	if len(s.encode('utf-8')) >= 35 * 1024:
		print("Invalid pool length.")
		return False
	if not isinstance(s, str):
		print("Invalid pool string.")
		return False
	try:
		decoded = base64.b64decode(s, validate=True)
		validblob = analyze_blob(decoded)
		if validblob["is_media"]:
			print(f"[!] Warning: Uploaded blob matches media fingerprint.")
			return False
		if validblob["entropy"] < 7.5:
			print(f"[!] Warning: Uploaded blob entropy is low ({inspection['entropy']:.2f})")
			return False
		return True
	except (base64.binascii.Error, ValueError):
		print("Invalid pool base64 value.")
		return False

def is_sha256_hash(poolidhash: str) -> bool:
	return bool(re.fullmatch(r'[a-fA-F0-9]{64}', poolidhash))

class ShredFS(LoggingMixIn, Operations):

	def __init__(self, backing_dir):
		self.backing = os.path.realpath(backing_dir)
		self.read_counts = defaultdict(int)
		self.read_lock = Lock()
		self.expiry_seconds = 600
		self.cleanup_thread = threading.Thread(target=self._cleanup_expired_files, daemon=True)
		self.cleanup_thread.start()

	def _cleanup_expired_files(self):
		while True:
			now = time.time()
			for root, dirs, files in os.walk(self.backing):
				for name in files:
					path = os.path.join(root, name)
					try:
						mtime = os.path.getmtime(path)
						if now - mtime > self.expiry_seconds:
							self._shred_and_delete(path)
					except Exception as e:
						print(f"[!] Cleanup error for {path}: {e}")
			time.sleep(30)

	def _full_path(self, path: str) -> str:
		candidate = os.path.realpath(os.path.join(self.backing, path.lstrip("/")))
		if not candidate.startswith(self.backing + os.sep):
			raise FuseOSError(errno.EACCES)
		return candidate

	def getattr(self, path, fh=None):
		full = self._full_path(path)
		try:
			st = os.lstat(full)
			return {key: getattr(st, key) for key in ('st_mode', 'st_size', 'st_uid', 'st_gid', 'st_ctime', 'st_mtime', 'st_atime')}
		except OSError:
			raise FuseOSError(errno.ENOENT)

	def readdir(self, path, fh):
		full = self._full_path(path)
		return ['.', '..'] + os.listdir(full)

	def create(self, path, mode, fi=None):
		full = self._full_path(path)
		return os.open(full, os.O_WRONLY | os.O_CREAT, mode)

	def open(self, path, flags):
		full = self._full_path(path)
		return os.open(full, flags)

	def read(self, path, size, offset, fh):
		with self.read_lock:
			self.read_counts[path] += 1

		os.lseek(fh, offset, os.SEEK_SET)
		data = os.read(fh, size)

		if self.read_counts[path] == 1:
			full = self._full_path(path)
			try:
				self._shred_and_delete(full)
			except Exception as e:
				print(f"[!] Error shredding {path}: {e}")

		return data

	def write(self, path, data, offset, fh):
		os.lseek(fh, offset, os.SEEK_SET)
		return os.write(fh, data)

	def unlink(self, path):
		os.unlink(self._full_path(path))

	def _shred_and_delete(self, filepath):
		filesize = os.path.getsize(filepath)
		with open(filepath, 'ba+', buffering=0) as f:
			for _ in range(3):
				f.seek(0)
				f.write(os.urandom(filesize))
		os.remove(filepath)
		print(f"[+] Shredded and deleted: {filepath}")
		with open('/sepc/msgcount.txt', 'r') as file:
			number = int(file.read().strip())
		number += 1
		with open('/sepc/msgcount.txt', 'w') as file:
			file.write(str(number))

class PoolPayload(BaseModel):
	data: str

app = FastAPI()
backing_dir = '/sepc/BAK'
mount_point = '/sepc/MNT'
active_pools = []

@app.on_event("startup")
def mount_fuse():
	if not os.path.exists(backing_dir):
		raise RuntimeError(f"Backing directory '{backing_dir}' does not exist.")

	def run_fuse():
		shred_fs = ShredFS(backing_dir)
		FUSE(shred_fs, mount_point, nothreads=True, foreground=True)

	thread = threading.Thread(target=run_fuse, daemon=True)
	thread.start()

@app.get("/pool/{PoolID}")
def pool_call(PoolID: str):
	if is_sha256_hash(PoolID) and PoolID in active_pools:
		with open(f"{mount_point}/{PoolID}", "r") as f:
			pool = f.read()
		active_pools.remove(PoolID)
		return {"data": pool}
	else:
		return {"data": "X"}

@app.put("/pool/{PoolID}")
def upload_pool(PoolID: str, payload: PoolPayload):
	validname = is_sha256_hash(PoolID)
	validdata = is_valid_pool(payload.data)
	if validname and validdata:
		if PoolID not in active_pools:
			try:
				decoded = base64.b64decode(payload.data, validate=True)
				inspection = analyze_blob(decoded)
				if inspection["is_media"]:
					print(f"[!] Warning: Uploaded blob matches media fingerprint.")
				if inspection["entropy"] < 7.5:
					print(f"[!] Warning: Uploaded blob entropy is low ({inspection['entropy']:.2f})")
				with open(f"{mount_point}/{PoolID}", "wb") as f:
					f.write(payload.data.encode("utf-8"))
				active_pools.append(PoolID)
				return {"PoolID": PoolID}
			except Exception as e:
				print(f"[!] Upload failed: {e}")
				return {"PoolID": "X"}
		else:
			return {"PoolID": "X"}
	else:
		print(PoolID)
		print(payload.data)
		return {"PoolID": "X"}

