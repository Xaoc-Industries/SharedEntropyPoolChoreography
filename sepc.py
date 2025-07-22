from cryptography.hazmat.primitives.ciphers.aead import AESGCM, AESSIV
from urllib.parse import urlparse
import re
import base64
import requests
import json
import zlib
import argparse
import os
import hashlib
import time
import secrets
import sys

def is_url(string):
    url_pattern = re.compile(
        r'^(?:http|ftp)s?://'
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]*[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'
        r'localhost|'
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
        r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'
        r'(?::\d+)?'
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(url_pattern, string) is not None

def pool_maker(hf_host, aeskey):
	retry = True
	while retry:
		chars = "!#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{|}~"
		target_size = 25 * 1024
		required = list(chars)
		_sr.shuffle(required)
		pooldata = ''
		written = len(required)
		chunk_size = 1024 * 1024
		allchars = ''
		found_chars: set[str] = set()
		while len(found_chars) < len(chars):
			if written < target_size:
				remaining = target_size - written
				this_chunk_size = min(chunk_size, remaining)
				chunk = ''.join(_sr.choices(chars, k=this_chunk_size))
				pooldata += chunk
				written += this_chunk_size
				found_chars.update(chunk)
			else:
				required = list(chars)
				_sr.shuffle(required)
				pooldata = ''
				written = 0
				found_chars.clear()
		sha256_hash = hashlib.sha256()
		sha256_hash.update(pooldata.encode('ascii'))
		shahash = sha256_hash.hexdigest()
		genat = int(time.time())
		expat = genat + 600
		poolid = _sr._randbelow(999_999_999) + 1
		poolidhash = hashlib.sha256()
		poolidhash.update(str(poolid).encode('ascii'))
		poolidhash = poolidhash.hexdigest()
		out = json.dumps({
			"PoolID": str(poolid),
			"TTL": expat,
			"GeneratedAt": genat,
			"EnSrc": "V1.1",
			"SHA256": shahash,
			"Data": pooldata
		})
		outbytes = out.encode("utf-8")
		assert len(aeskey) == 64
		aes_siv = AESSIV(aeskey)
		associated_data = ["Data".encode("ascii")]
		binary_encrypted_pool = aes_siv.encrypt(outbytes, associated_data)
		b64_encrypted_pool = base64.b64encode(binary_encrypted_pool).decode('ascii')
		url = f"{hf_host}/{poolidhash}"
		try:
			response = requests.put(url, json={"data": b64_encrypted_pool})
		except:
			raise SystemExit("Encode Failed: Failed to contact pool vault.")
		if response.status_code == 200:
			replydata = response.json()
			if replydata["PoolID"] != 'X':
				retry = False
		else:
			raise SystemExit("Encode Failed: Pool upload failed.")
	return out, poolidhash

def digester(CurrentPool):
	required_chars = list('+/0123456789=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz')
	EntropyPool = json.loads(CurrentPool)
	EntropyPoolBytes = EntropyPool["Data"].encode('ascii', errors='ignore')
	PoolIndexes = {}
	for char in required_chars:
		target_byte = ord(char)
		matches = [i for i, byte in enumerate(EntropyPoolBytes) if byte == target_byte]
		PoolIndexes[target_byte] = matches
	return PoolIndexes

def reference_mapper(PIndexes, SecretSrc):
	with open(SecretSrc, 'rb') as f:
		raw_bytes = f.read()
	b64 = base64.b64encode(raw_bytes).decode('ascii')
	host_payload_index_map = []
	for char in b64:
		byte_val = ord(char)
		indexes = PIndexes.get(byte_val)
		host_payload_index_map.append(secrets.choice(indexes))
	encoded_indexes = ''
	for index in host_payload_index_map:
		index_str = str(index)
		index_char_length = str(len(index_str))
		encoded_indexes += index_char_length + index_str
	return encoded_indexes

def cryptor(CStr, LIC, SegLen, SEED):
	remainder = len(CStr) % SegLen
	if remainder != 0:
		pad_len = SegLen - remainder
		CStr += '0' * pad_len
	segments = [CStr[i:i+SegLen] for i in range(0, len(CStr), SegLen)]
	lic_bytes = LIC.encode('ascii')
	key_primal = sum(lic_bytes)
	key = key_primal * SEED
	payload = ""
	first_loop = True
	loop_count = 0
	for segment in segments:
		segment = segment.zfill(SegLen)
		segment_int = int(segment)
		encoded_segment = key ^ segment_int
		segment_bytes = segment.encode('ascii')
		loop_count += 1
		key_primal = sum(segment_bytes)
		key = key_primal * (SEED + (loop_count * SegLen))
		if first_loop:
			payload = str(encoded_segment)
			first_loop = False
		else:
			payload += "*" + str(encoded_segment)
	BytesPLD = payload.encode('ascii')
	CompressedPLD = zlib.compress(BytesPLD, level=9)
	return CompressedPLD

def decoder(EnCh, LIC, SegLen, SEED, CurrentPool):
	payload_segments = EnCh.split('*')
	payload_int_data = ''
	lic_bytes = LIC.encode('ascii')
	key_primal = sum(lic_bytes)
	key = key_primal * SEED
	loop_count = 0
	for segment in payload_segments:
		this_decoded_content = str(int(segment) ^ key)
		if len(this_decoded_content) < SegLen:
			this_decoded_content = this_decoded_content.zfill(SegLen)
		payload_int_data += this_decoded_content
		decoded_bytes = this_decoded_content.encode('ascii')
		loop_count += 1
		key = sum(decoded_bytes) * (SEED + (loop_count * SegLen))
	EntropyPool = json.loads(CurrentPool)
	EntropyPoolBytes = EntropyPool["Data"].encode('ascii', errors='ignore')
	current_string_index = 0
	b64 = ''
	current_index = 0
	indices = []
	while current_index < len(payload_int_data):
		length_char = payload_int_data[current_index]
		length = int(length_char)
		current_index += 1
		index_str = payload_int_data[current_index : current_index + length]
		indices.append(index_str)
		current_index += length
	b64 = ""
	for index in indices:
		if index and 0 <= int(index) < len(EntropyPoolBytes):
			b64 += chr(EntropyPoolBytes[int(index)])
	return b64

def main():
	if sys.argv[1] == "?":
		print("Usage:")
		print("--------------------------------------------------------------------------------")
		print("|                                    ENCODE                                    |")
		print("--------------------------------------------------------------------------------")
		print(" sepc                                                                           ")
		print("      -s [PATH TO SECRET]                                                       ")
		print("      -p [Pool Vault URL]                                                       ")
		print("      -l [Password String] (Just a random password)                             ")
		print("      -sl [Segment Length] (A Number 5-50)                                      ")
		print("      -sv [Seed Value] (Large Number 10000-999999999)                           ")		
		print("      -o [Output Path]                                                          ")
		print("--------------------------------------------------------------------------------")
		print("--------------------------------------------------------------------------------")
		print("|                                    DECODE                                    |")
		print("--------------------------------------------------------------------------------")
		print(" sepc                                                                           ")
		print("      -d [PATH TO PLD]                                                          ")
		print("      -p [Pool URL or File Path]                                                ")
		print("      -l [Password String] (Just a random password)                             ")
		print("      -sl [Segment Length] (A Number 5-50)                                      ")
		print("      -sv [Seed Value] (Large Number 10000-999999999)                           ")		
		print("      -o [Output Path]                                                          ")
		print("--------------------------------------------------------------------------------")
		print("--------------------------------------------------------------------------------")
		print("|                                   ARCHIVE                                    |")
		print("--------------------------------------------------------------------------------")
		print(" sepc                                                                           ")
		print("      -a [Pool Vault URL]                                                       ")
		print("      -o [Output Path]                                                       ")
		print("--------------------------------------------------------------------------------")
		print("--------------------------------------------------------------------------------")
		print("|                                    RECALL                                    |")
		print("--------------------------------------------------------------------------------")
		print(" sepc                                                                           ")
		print("      -r [Pool Vault URL]                                                       ")
		print("--------------------------------------------------------------------------------")
		sys.exit()
	else:
		parser = argparse.ArgumentParser(description="HekateForge SEPC Tool")
		parser.add_argument("-s", "--secret", help="Path to the secret message file")
		parser.add_argument("-p", "--pool", help="URL to the entropy pool source")
		parser.add_argument("-l", "--lic", help="LIC value")
		parser.add_argument("-sl", "--segment_length", type=int, help="Segment length")
		parser.add_argument("-sv", "--seed", type=int, help="Seed value")
		parser.add_argument("-o", "--output", help="Output path of function")
		parser.add_argument("-d", "--decrypt", help="Path to PLD for decryption mode")
		parser.add_argument("-r", "--recall", help="PoolID to recall")
		parser.add_argument("-a", "--archive", help="PoolID to archive")
		args = parser.parse_args()
		required_fields = [args.pool, args.lic, args.segment_length, args.seed, args.output]
		if args.recall:
			RecallPool = args.recall
			OutputFile = args.output
			try:
				print(f"Recalling pool {RecallPool}")
				encrypted_poolb64reply = requests.get(RecallPool)
			except:
				raise SystemExit("Failed to contact pool vault.")
			if encrypted_poolb64reply.status_code == 200:
				encrypted_poolb64 = encrypted_poolb64reply.json()
				encrypted_poolb64reply = ''
				encrypted_poolb64 = ''
				sys.exit()
			else:
				raise SystemExit("Failed to retrieve pool.")
		elif args.archive:
			if args.output:
				ArchivePool = args.archive
				OutputFile = args.output
				try:
					print(f"Archiving pool {ArchivePool} to file {OutputFile}")
					encrypted_poolb64reply = requests.get(ArchivePool)
				except:
					raise SystemExit("Failed to contact pool vault.")
				if encrypted_poolb64reply.status_code == 200:
					encrypted_poolb64 = encrypted_poolb64reply.json()
					with open(OutputFile, "w") as q:
						json.dump(encrypted_poolb64, q)
						sys.exit()
				else:
					raise SystemExit("Failed to retrieve pool.")
			else:
				raise SystemExit("No output file specified.")
		if args.secret and args.decrypt:
			raise SystemExit("-s and -d must be used independently.")
		if not all(required_fields):
			raise SystemExit("All arguments -s/d, -p, -l, -sl, -sv, and -o must be provided.")
		if args.secret:
			SecretPath = args.secret
			print(f"Encoding {SecretPath}...")
			PoolDest = args.pool
			LICVAL = args.lic
			aeskey = hashlib.sha512(LICVAL.encode("ascii")).digest()
			SegmentLength = args.segment_length
			SeedVal = args.seed
			PLDPath = str(args.output) + ".PLD"
			Pool, PoolID = pool_maker(PoolDest, aeskey)
			SelectedPoolIndexes = digester(Pool)
			ChStr = reference_mapper(SelectedPoolIndexes, SecretPath)
			PLDCompressed = cryptor(ChStr, LICVAL, SegmentLength, SeedVal)
			MetaData = f"sepc -d ./{os.path.splitext(os.path.basename(args.output))[0]}.PLD -p {args.pool}/{PoolID} -l {args.lic} -sl {args.segment_length} -sv {args.seed} -o ./{os.path.splitext(os.path.basename(args.secret))[0]}{os.path.splitext(os.path.basename(args.secret))[1]}; rm {os.path.splitext(os.path.basename(args.output))[0]}.PLD; rm {os.path.splitext(os.path.basename(args.output))[0]}.sh"
			metadata_path = os.path.dirname(PLDPath)
			metadata_filename = os.path.splitext(os.path.basename(PLDPath))[0]
			metadata_file = f"{metadata_path}/{metadata_filename}.sh"
			with open(PLDPath, "wb") as f:
				f.write(PLDCompressed)
			with open(metadata_file, "w") as g:
				g.write(MetaData)
		elif args.decrypt:
			PLDPath = args.decrypt
			print(f"Decoding {PLDPath}...")
			PoolSource = args.pool
			LICVAL = args.lic
			aeskey = hashlib.sha512(LICVAL.encode("ascii")).digest()
			assert len(aeskey) == 64
			aes_siv = AESSIV(aeskey)
			SegmentLength = args.segment_length
			SeedVal = args.seed
			OutputPath = args.output
			remote_pool = is_url(PoolSource)
			if remote_pool:
				try:
					encrypted_poolb64reply = requests.get(PoolSource)
					if encrypted_poolb64reply.status_code == 200:
						encrypted_poolb64 = encrypted_poolb64reply.json()
					else:
						raise SystemExit("Failed to retrieve pool.")
				except:
					raise SystemExit("Failed to contact pool vault.")
			else:
				try:
					with open(PoolSource, "r") as h:
						encrypted_poolb64 = json.load(h)
				except:
					raise SystemExit("Local pool read failed.")
			if encrypted_poolb64 == "X":
				raise SystemExit("Decode Failed: Pool unavailable.")
			try:
				encrypted_pool = base64.b64decode(encrypted_poolb64["data"])
			except:
				raise SystemExit("Decode Failed: No returned pool or returned pool is invalid.")
			associated_data = ["Data".encode("ascii")]
			try:
				Pool = aes_siv.decrypt(encrypted_pool, associated_data)
				Pool = Pool.decode("utf-8")
			except:
				raise SystemExit("Decode Failed: Bad pool decrypt.")
			with open(PLDPath, 'rb') as f:
				PLDzip = f.read()
			PLD = zlib.decompress(PLDzip).decode('ascii')
			try:
				DecodeB64 = decoder(PLD, LICVAL, SegmentLength, SeedVal, Pool)
			except:
				raise SystemExit("Decode Failed: No valid message.")
			with open(OutputPath, "wb") as f:
				try:
					f.write(base64.b64decode(DecodeB64))
				except:
					raise SystemExit("Decode Failed: No valid message.")
		else:
			raise SystemExit("No argument provided.")
		print("Done!")
if __name__ == "__main__":
	print("-:-::-:-::-:-------------==-=-=---==------------+----=--------===-==-===========")
	print(":------:-:::-----:------=--=-----=-------------=-----------------===============")
	print(":::---:::-:---:-:-------------=----------------------=+-----------==============")
	print("-:-::-:-:-::::-:-----------=--=-==*==-------------=----+-----=-=-=-=============")
	print("---:-----:-:-----------------=*##%**##=----------=*#=---=---=-==-===============")
	print("-----:-:--------------------=#%%%%%==+%=--------=#*%%*=-----=---================")
	print("------:---------:--------=--*#%%%%%%=#%%+-------*#%%%%##=--=-=---===============")
	print("-:------:-:------------------*%#*%###%#+--------+*##%%##=----==-================")
	print(":--:---:-:::----------------=#%%#%###%**-------==+#%%%%%*=-=---=================")
	print("::-------:------------------=*#%%#%###%%=------=**#+*%%%#===-=-=========+=======")
	print("--------------------------++#%%%#%#*%#%%+=-=+--==+##%%%%%=======================")
	print("------------------------==-=###%%##%%###*--=--+*+%*%%%%#+--=====================")
	print("-----------:---------=--==*++*%##%%**##+--==-+=##*%%%%*===-=====================")
	print("----------------=-=--------+-*+#**++#%#=-=-===-**%%%%%#====-====================")
	print("--------------==++++%*#+----==++===-==----+==+=+=*%%%%#========+================")
	print("-------------==*%%%#**##*------=+=+*=+==------===*=%%%==========================")
	print("---:---------+####%%*##*#*------=##++-=-=+++-+===+*+*=-=========================")
	print("-------------*##%#%%#+**#+---=--=-----=-=++-=*--==================*=+===========")
	print("------------*###%###%%*#*#-----------=--===*+=*====+-==========++=+**+====+=====")
	print("------=----=+###%####*+**==-----------------*-=-=-==-+========++*=#**%%=========")
	print("-------=---=+#*#%##+%*#=+=--------------=-----===============+=++**#%%%+========")
	print("-----------=+*###*#*===+---==-+=*=+=+--==---==--==--=-==+=======+++#%%%+========")
	print("-----------==++##*###+*=---=*=*+--++##**=-------====-=====+====#+**+#%%%========")
	print("----------------+***#*+#--==-----*#*#%***#%*+=--===========##*=+=+*#%%%%========")
	print("-------------=---==-=----=+-=+*#**#***#%%#%*%#%+-===-=======+===+*#%%%%+========")
	print("------------=---=++=+*--+--=+=+-=+#+*####*#%%%%*%%============+=+*+*%%%=========")
	print("----------+=--*===#===+*=+-=====*+#****#%##%#%#%*##=============*#+**%+=========")
	print("--------------=-+=-==---===+=+*+-=#*+#+%#%%##%%%%%%=======+=====*+++#+==========")
	print("-----------=------=---==#*#*=+##+==-===%%#%#*##%*#%%=======++===+=*=*##+========")
	print("----------==+-+-=-=*#+%#*###*%#*#*###*#+##***#%#%##%==========*=====+#++=====++=")
	print("------=-==+=-==-=#%%%%%%%%%#%%%%%%%+*#*%+%%#%%%%##**================++++======++")
	print("-----------+--==+###%#%%%%%%%%###%%##*####%##%#**##**#=+==============*=====+++=")
	print("------------===-+#####%%#%%%%#%#%%+%+#*###*#%*#%#*%++%##+===================++++")
	print("-------=-===-=---%%%#%%%%%%%%%%#*=+%#*%##%#%##%##%#*=*#%*=================+=++++")
	print("---------=--+-===*#%%%%%%#%%%%%%+==#*#%#*%#*#%#%#%+===#*#+================+++=++")
	print("-------------===+#%#%#%%%%%%*#%*=#+*=#+*%###%%%#%*====##*=================++++++")
	print("-------=-=----+#*#%#%%%%%%%%#*====++*+#+#%##%#*%#======+===============+++++++++")
	print("------------====+=+=*%%%%#*+==++=====%==++##+==============================+++++")
	print("----=--========++=*++=-======+==+======================================+=+=+++++")
	print("------====+===+=+====+========+====================================+======++++++")
	print("-----=-====+==++++=============+=======*===========================*+=+===++++++")
	print("---=-===+-==++=*===-===-=============================+===============++=++++++++")
	print("---==-=======++=+==================================================+=+=+++++++++")
	print("---=-=====+====+-=================================================++===+++++++++")
	print("==-======-=====*==================================================++++++++++++++")
	print("################################################################################")
	print(" HekateForge SEPC Beta V1.1 - Dedicated to Jenga: 2014 - July 18th 2025 12:30PM ")
	print("                            ~May she rest in peace~                             ")
	print("################################################################################")
	_sr = secrets.SystemRandom()
	main()
