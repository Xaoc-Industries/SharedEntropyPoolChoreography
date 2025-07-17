from fastapi import FastAPI, HTTPException, Body
from pydantic import BaseModel
import os
import errno
import sys
import threading
from fusepy import FUSE, FuseOSError, LoggingMixIn, Operations
from collections import defaultdict
from threading import Lock

class ShredFS(LoggingMixIn, Operations):
	def __init__(self, backing_dir):
		self.backing = os.path.realpath(backing_dir)
		self.read_counts = defaultdict(int)
		self.read_lock = Lock()

	def _full_path(self, path):
		return os.path.join(self.backing, path.lstrip("/"))

	def getattr(self, path, fh=None):
		full = self._full_path(path)
		try:
			st = os.lstat(full)
			return dict((key, getattr(st, key)) for key in ('st_mode', 'st_size', 'st_uid','st_gid', 'st_ctime', 'st_mtime', 'st_atime'))
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

class PoolPayload(BaseModel):
    Data: str

app = FastAPI()
backing_dir = '/SEPC/BAK'
mount_point = '/SEPC/MNT'
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
	if PoolID in active_pools:
		with open(f"{mount_point}/{PoolID}", "r") as f:
			pool = f.read()
		active_pools.remove(PoolID)
		return {"data": pool}
	raise HTTPException(status_code=404, detail="PoolID not active")

@app.put("/pool/{PoolID}")
def upload_pool(PoolID: str, payload: PoolPayload):
	if PoolID not in active_pools:
		with open(f"{mount_point}/{PoolID}", "wb") as f:
			f.write(payload.Data.encode("utf-8"))
		active_pools.append(PoolID)
		return {"PoolID": PoolID}
	else:
		return {"PoolID": "X"}

