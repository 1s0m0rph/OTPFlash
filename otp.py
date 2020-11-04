desc = """
Contains code for both running the OTP algorithm on some file (generally assumed to be a zip file) and for flashing a drive with cryptographic random bits to use as an OTP key
"""

from secrets import randbits
from os import listdir,remove
from os.path import isdir,exists,getsize
import argparse

KEYFILE_NAME = "otpkey"#we'll check to make sure this isn't already on the drive we're flashing to before overwriting (the process will clear everything on thedrive)
KEYFILE_ENCRYPT_START_AT = "otpestart"
KEYFILE_DECRYPT_START_AT = "otpdstart"

'''
drivesize and write_batch should be in bytes
'''
def write_new_key_to_ext_drive(key_len_bytes, driveloc, write_batch_bytes, verbose, squash):
	if (driveloc[-1] != '/') and (driveloc[-1] != '\\'):
		driveloc += '/'
	#first check that this drive exists
	if not isdir(driveloc):
		raise AttributeError("location {} not recognized as a directory".format(driveloc))
	#now check that there isn't a keyfile here
	keyf_loc = driveloc + KEYFILE_NAME
	keyf_estart_loc = driveloc+KEYFILE_ENCRYPT_START_AT
	keyf_dstart_loc = driveloc+KEYFILE_DECRYPT_START_AT
	if (not squash) and exists(keyf_loc):
		raise KeyError("An OTP keyfile already exists in directory {}".format(driveloc))
	if (not squash) and exists(keyf_estart_loc):
		raise KeyError("An OTP encryption start index file already exists in directory {}".format(driveloc))
	if (not squash) and exists(keyf_dstart_loc):
		raise KeyError("An OTP decryption start index file already exists in directory {}".format(driveloc))
	#delete the contents of this directory
	dircon = listdir(driveloc)
	for f in dircon:
		try:
			remove(driveloc + f)
		except PermissionError:
			pass#this usually means access denied, which is because listdir will give system files too

	if verbose:
		print("All prechecks passed, generating key.")

	#now actually make/flash the keyfile
	nbatch = (key_len_bytes//write_batch_bytes)+1
	bytes_rem = key_len_bytes
	i = 0
	with open(keyf_loc,'wb') as kf:
		while bytes_rem > 0:
			print("{} of {} batches  (size = {} bytes) competed ({:.2f}%)".format(i,nbatch,write_batch_bytes,100*(i/nbatch)))
			rns = bytearray([randbits(8) for _ in range(min(write_batch_bytes,bytes_rem))])
			kf.write(rns)
			i += 1
			bytes_rem -= write_batch_bytes#could go negative at the end but whatever
	#write the start files (this is just a single integer that tells us how many bytes have already been used for en/decryption)
	with open(keyf_estart_loc,'w') as f:
		f.write("0")
	with open(keyf_dstart_loc,'w') as f:
		f.write("0")


def en_de_crypt(input_text,input_key,output,batch_size,verbose,squash,encrypt):
	if not exists(input_textfile):
		raise FileNotFoundError("Input textfile {} not found".format(input_text))
	if (input_key[-1] != '/') and (input_key[-1] != '\\'):
		input_key += '/'
	if not isdir(input_key):
		raise NotADirectoryError("Keyfile input must be in the form of a directory with a keyfile and two startfiles")

	key_estart = input_key + KEYFILE_ENCRYPT_START_AT
	key_dstart = input_key + KEYFILE_DECRYPT_START_AT
	input_key = input_key + KEYFILE_NAME
	if not exists(input_keyfile):
		raise FileNotFoundError("Input keyfile {} not found".format(input_key))
	if not exists(key_estart):
		raise FileNotFoundError("No encryption keystart file found.")
	if not exists(key_dstart):
		raise FileNotFoundError("No decryption keystart file found.")
	if exists(output):
		emsg = "output file already exists: {}".format(output)
		if squash:#just warn
			print("WARNING: " + emsg)
		else:
			raise FileExistsError(emsg)

	tsize = getsize(input_text)
	ksize = getsize(input_key)


	estart = 0
	dstart = 0
	with open(key_estart,'r') as f:
		estart = int(f.readline())
	with open(key_dstart,'r') as f:
		dstart = int(f.readline())
	if dstart > estart:
		raise ValueError("OTP key reuse detected. DO NOT REUSE OTP KEYS")
	start_at_byte = estart if encrypt else dstart

	if tsize > (ksize - start_at_byte):
		raise ValueError("Key must be at least as long as input. ({} (input) > {} (keylength remaining))".format(tsize,ksize - start_at_byte))

	if verbose:
		print("All prechecks passed, en/decrypting.")

	nbatch = (tsize//batch_size) + 1
	bytes_rem = tsize
	i = 0
	with open(input_key, 'rb') as key:
		if start_at_byte > 0:
			#throw out the first few (already used) bytes of the key
			key.read(start_at_byte)
		with open(input_text,'rb') as inp:
			with open(output,'wb') as out:
				while bytes_rem > 0:
					print("{} of {} batches  (size = {} bytes) competed ({:.2f}%)".format(i, nbatch, batch_size,100*(i/nbatch)))
					#get this batch's bytes
					nb_this = min(bytes_rem,batch_size)
					textb = inp.read(nb_this)#should be a bytearray
					keyb = key.read(nb_this)
					#XOR these together
					o = bytearray([a ^ b for a,b in zip(textb,keyb)])
					#output
					out.write(o)
					i += 1
					bytes_rem -= nb_this

	#update the en/decrypt indices
	if encrypt:
		#update the encryption file
		with open(key_estart,'w') as f:
			f.write(str(tsize))
	else:
		#update the decryption file
		with open(key_dstart,'w') as f:
			f.write(str(tsize))


if __name__ == '__main__':
	parser = argparse.ArgumentParser(description=desc)

	#GENERAL ARGS
	parser.add_argument('-m','--mode',nargs=1,type=str,default=[''],choices=['e','encrypt','d','decrypt','f','flash'],help="What mode should the program run in? Choices are en/decrypt and flash (for creating keyfiles).")
	parser.add_argument('-v','--verbose',action='store_true',default=False)
	parser.add_argument('-s','--squash_old',default=False,action='store_true',help="Should I delete old output files with the same name?")

	#FLASH-SPECIFIC
	parser.add_argument('-f','--flash_loc',nargs=1,type=str,default=[''],help="What directory should contain the keyfile?")
	parser.add_argument('-b','--key_bytes',nargs=1,type=int,default=[0],help="How many bytes should the generated key be? (generally this should be a MB or so less than the size of the flash drive)")
	parser.add_argument('-B','--batch_size',nargs=1,type=int,default=[1<<20],help="How many bytes should be read/written at one time? (smaller numbers are less RAM-intensive but more hard drive intensive)")

	#EN/DECRYPTION-SPECIFIC
	parser.add_argument('-i','--input_textfile',nargs=1,type=str,default=[''],help="Where can I find the file you wish the en/decrypt?")
	parser.add_argument('-k','--input_keyfile',nargs=1,type=str,default=[''],help='Where can I find the OTP keyfile? Must include only the path to the key directory.'.format(KEYFILE_NAME))
	parser.add_argument('-o','--output_file',nargs=1,type=str,default=[''],help="Where should I output the en/decrypted file? (include extension if decrypting)")

	args = parser.parse_args()

	verbose = args.verbose
	squash = args.squash_old

	run_en_decryption = args.mode[0] in ['e','encrypt','d','decrypt']
	for_encryption = args.mode[0] in ['e','encrypt']
	run_flash = args.mode[0] in ['f','flash']
	if (not run_en_decryption) and (not run_flash):
		raise AttributeError("Running mode not recognized: {}".format(args.mode))

	flash_loc = args.flash_loc[0]
	key_bytes = args.key_bytes[0]
	batch_size_bytes = args.batch_size[0]

	if run_flash:
		if key_bytes <= 0:
			raise AttributeError("Key must be at least 1 byte long. (--key_bytes=[number])")

		write_new_key_to_ext_drive(key_bytes,flash_loc,batch_size_bytes,verbose,squash)
	elif run_en_decryption:
		input_textfile = args.input_textfile[0]
		input_keyfile = args.input_keyfile[0]
		output_file = args.output_file[0]
		en_de_crypt(input_textfile,input_keyfile,output_file,batch_size_bytes,verbose,squash,for_encryption)