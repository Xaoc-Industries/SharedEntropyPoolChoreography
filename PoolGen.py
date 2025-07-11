import os
import random
import hashlib
import time
import argparse

def main():
	parser = argparse.ArgumentParser(description="HekateForge SEPC Pool Generation Tool")
	parser.add_argument("-o", "--output", help="Output path of pool")
	args = parser.parse_args()
	OutputPath = args.output
	if args.output:
		chars = "!#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{|}~"
		target_size = 25 * 1024
		required = list(chars)
		random.shuffle(required)
		pooldata = ''
		out = ''
		with open(OutputPath, "w", encoding="ascii") as f:
			written = len(required)
			chunk_size = 1024 * 1024
			while written < target_size:
				chunk = ''.join(random.choices(chars, k=chunk_size))
				if written + chunk_size > target_size:
					chunk = chunk[:target_size - written]
				pooldata += chunk
				written += len(chunk)
			sha256_hash = hashlib.sha256()
			sha256_hash.update(chunk.encode('ascii'))
			shahash = sha256_hash.hexdigest()
			genat = int(time.time())
			genatstr = str(genat)
			expat = genat + 600
			expatstr = str(expat)
			out = f'''{{
			"PoolID": "0",
			"TTL": {expatstr},
			"GeneratedAt": {genatstr},
			"EnSrc": "V1",
			"SHA256": "{shahash}",
			"Data": "{pooldata}"
		}}'''
			f.write(out)
	else:
		raise ArgumentError("No output specified.")

if __name__ == "__main__":
	print("--------------------------------------------------------------------------------")
	print("                                                                                ")
	print(" HekateForge SEPC POOL MAKER BETA Version 1.0 - Patent Pending William Appleton ")
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
