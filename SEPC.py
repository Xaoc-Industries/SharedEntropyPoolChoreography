import base64
import requests
import json
import random
import zlib
import argparse

def digester(EntropyPoolID):
	required_chars = list('+/0123456789=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz')
	response = requests.get(EntropyPoolID)
	if response.status_code == 200:
		EntropyPool = json.loads(response.text)
	else:
		raise ConnectionError(f"Failed to fetch entropy pool from {EntropyPoolID}")
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
	b64 = base64.b64encode(raw_bytes).decode('ascii')  # fix here
	host_payload_index_map = []
	for char in b64:
		byte_val = ord(char)
		indexes = PIndexes.get(byte_val)
		if not indexes:
			raise ValueError(f"No matches for byte {byte_val} in entropy pool")
		host_payload_index_map.append(random.choice(indexes))
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

def decoder(EnCh, LIC, SegLen, SEED, EntropyPoolID):
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
	response = requests.get(EntropyPoolID)
	if response.status_code == 200:
		EntropyPool = json.loads(response.text)
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
	parser = argparse.ArgumentParser(description="HekateForge SEPC Tool")
	parser.add_argument("-s", "--secret", help="Path to the secret message file")
	parser.add_argument("-p", "--pool", help="URL to the entropy pool source")
	parser.add_argument("-l", "--lic", help="LIC value")
	parser.add_argument("-sl", "--segment_length", type=int, help="Segment length")
	parser.add_argument("-sv", "--seed", type=int, help="Seed value")
	parser.add_argument("-o", "--output", help="Output path of function")
	parser.add_argument("-d", "--decrypt", help="Path to PLD for decryption mode")
	args = parser.parse_args()
	required_fields = [args.pool, args.lic, args.segment_length, args.seed, args.output]
	if not all(required_fields):
		parser.error("All arguments -s/d, -p, -l, -sl, -sv, and -o must be provided.")
		quit()
	if args.secret:
		SecretPath = args.secret
		PoolSource = args.pool
		LICVAL = args.lic
		SegmentLength = args.segment_length
		SeedVal = args.seed
		PLDPath = args.output
		SelectedPoolIndexes = digester(PoolSource)
		ChStr = reference_mapper(SelectedPoolIndexes, SecretPath)
		print(f"Encoding {SecretPath}...")
		PLDCompressed = cryptor(ChStr, LICVAL, SegmentLength, SeedVal)
		with open(PLDPath, "wb") as f:
			f.write(PLDCompressed)
	elif args.decrypt:
		PoolSource = args.pool
		LICVAL = args.lic
		SegmentLength = args.segment_length
		SeedVal = args.seed
		PLDPath = args.decrypt
		OutputPath = args.output
		with open(PLDPath, 'rb') as f:
			PLDzip = f.read()
		PLD = zlib.decompress(PLDzip).decode('ascii')
		print(f"Decoding {PLDPath}...")
		DecodeB64 = decoder(PLD, LICVAL, SegmentLength, SeedVal, PoolSource)
		with open(OutputPath, "wb") as f:
			f.write(base64.b64decode(DecodeB64))
	print("Done!")
if __name__ == "__main__":
	print("--------------------------------------------------------------------------------")
	print("                                                                                ")
	print("  HekateForge SEPC PROTOCOL BETA Version 1.0 - Patent Pending William Appleton  ")
	print("                                                                                ")
	print("--------------------------------------------------------------------------------")
	print("                                                                                ")
	print("                                \\            /                                  ")
	print("                                 \\    ()    /                                   ")
	print("                                  \\        /                                    ")
	print("                                   \\      /                                     ")
	print("                                ----\\--------                                   ")
	print("                                     \\  /   |                                   ")
	print("                                      \\/    |                                   ")
	print("                                            |                                   ")
	print("                                            |                                   ")
	print("                                -------------                                   ")
	print("                                                                                ")
	print("--------------------------------------------------------------------------------")
	print("                                                                                ")	
	main()
