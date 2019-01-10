import sys
import socket

from form_response import *
from easyzone import easyzone

IP = '127.0.0.1'
PORT = 5353
TYPES = ['']*29
ROOT_SERVERS = ['198.41.0.4', '192.228.79.201', '192.33.4.12', '199.7.91.13',
				'192.203.230.10', '192.5.5.241', '192.112.36.4', '128.63.2.53',
				'192.36.148.17', '192.58.128.30', '193.0.14.129', '199.7.83.42',
				'202.12.27.33']

answer_cache = []
path_cache = []


def GetResponseName(data):
	name = ''
	name_index = 12

	# skip headers
	data1 = data[12:]
	for byte in data1:
		if byte == 0:
			# got to Authoritative nameservers
			name_index += 5
			break
		name_index += 1

	real_index = int.from_bytes(data[name_index:name_index + 2], byteorder='big')-(1<<14|1<<15)

	while True:
		byte = data[real_index]
		if byte == 0:
			break
		for i in range(0, byte):
			name += chr(data[real_index+i+1])
		real_index += byte + 1
		name += '.'
	name = name[:-1]

	return name, int.from_bytes(data[name_index:name_index + 2], byteorder='big')


def GetA(response_servers, additional_rrs, authority_rrs, additional_index, data, response_name):
	for all_records in range(authority_rrs + additional_rrs):
		if len(response_servers) == authority_rrs:
			break
		isA = False
		if int.from_bytes(data[additional_index + 2: additional_index + 4], byteorder='big') == 1:
			isA = True
		additional_index += 10
		ip_len = int.from_bytes(data[additional_index: additional_index + 2], byteorder='big')
		if ip_len == 4 and isA:
			log_string = response_name[0] + '.\t' +\
						 str(int.from_bytes(data[additional_index - 4: additional_index], byteorder='big')) +\
						 '\tIN\tA\t'
			additional_index += 2
			new_ip = ''
			for byte in data[additional_index: additional_index + 4]:
				new_ip += str(byte) + '.'
			response_servers.append(new_ip[:-1])
			additional_index += ip_len
			print(log_string + new_ip[:-1])
		else:
			additional_index += 2 + ip_len
	return response_servers


def GetResponseServers(data, name_offset, response_name):
	response_servers = []
	authority_rrs = int.from_bytes(data[8:10], byteorder='big')
	additional_rrs = int.from_bytes(data[10:12], byteorder='big')

	additional_index = 12
	for byte in data[12:]:
		if byte == 0:
			additional_index += 5
			break
		additional_index += 1

	return GetA(response_servers, additional_rrs, authority_rrs, additional_index, data, response_name)


def RecursiveAnswer(data, servers, name, question_type):
	global path_cache

	response = b''
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

	# refactor to servers not servers[:1]
	for ip in servers:
		server_address = (ip, 53)
		sock.sendto(data, server_address)

		response, server = sock.recvfrom(512)
		response_name = GetResponseName(response)
		response_servers = GetResponseServers(response, response_name[1], response_name)
		if response_name[0] == name and int.from_bytes(response[6:8], byteorder='big') > 0:
			sock.close()
			print(name + '\t1800\tIN\t' + question_type + '\t' + ip)
			path_cache.append([name, ip])
			if len(path_cache) > 1000:
				path_cache = path_cache[1:]
			return response, True
		elif len(response_servers) > 0:
			response = RecursiveAnswer(data, response_servers, name, question_type)
			if response[1]:
				sock.close()
				print(name + '\t1800\tIN\t' + question_type + '\t' + ip)
				path_cache.append([name, ip])
				if len(path_cache) > 1000:
					path_cache = path_cache[1:]
				return response

	sock.close()
	return response, False


def SetTypes():
	TYPES[1] = 'A'
	TYPES[2] = 'NS'
	TYPES[5] = 'CNAME'
	TYPES[6] = 'SOA'
	TYPES[15] = 'MX'
	TYPES[16] = 'TXT'
	TYPES[28] = 'AAAA'


def GetName(data):
	name = ''
	index = 0

	while True:
		if data[index] == 0:
			break
		else:
			data_index = data[index]
			for i in range(0, data_index):
				index += 1
				name += chr(data[index])
			index += 1
			name += "."
	return name[:-1]


def GetQuestionType(data):
	type_index = 0
	for byte in data:
		if byte == 0:
			type_index += 1
			break
		type_index += 1
	return TYPES[int.from_bytes(data[type_index:type_index + 2], byteorder='big')]

#TODO
def IsRecord(data):
	return False


def GetHeaderSection(data, question_type, zone):
	# Transaction ID: TID
	trainsaction_id = data[:2]

	# Flags: QR|OPCODE|AA|TC|RD|RA|Z|RCODE
	flags = ((1<<15)|int.from_bytes(data[2:4], byteorder='big')).to_bytes(2, byteorder='big')

	# Questions: QDCOUNT
	questions = (1).to_bytes(2, byteorder='big')

	# Answer RRs: ANCOUNT
	answer_rrs = (len(zone.root.records(question_type).items)).to_bytes(2, byteorder='big')

	# Authority RRs: NSCOUNT
	authority_rrs = (0).to_bytes(2, byteorder='big')

	# Additonal RRs: ARCOUNT
	additional_rrs = (0).to_bytes(2, byteorder='big')

	response = trainsaction_id + flags + questions + answer_rrs  + authority_rrs + additional_rrs
	return response


def GetResponseSection(data, question_type, zone):
	print(";; ANSWER SECTION:")

	index = 12
	call_response = getattr(form_response, 'GetResponse' + question_type)
	response = call_response(question_type, zone, index)

	print("")
	return response


def GetResponse(data, config_path):
	global answer_cache
	global path_cache

	response = b''
	# get name
	name = GetName(data[12:])
	
	# if we have local record "is_record = True" else "False"
	is_record = IsRecord(data[12:])

	# A | NS | MX |TXT | SOA | AAAA | CNAME ?
	question_type = GetQuestionType(data[12:])

	if is_record:
		# set zone
		zone = easyzone.zone_from_file(name, config_path + name + ".conf")

		header_section = GetHeaderSection(data[0:12], question_type, zone)
		question_section = data[12:12 + len(name) + 2 + 4]
		response_section = GetResponseSection(data, question_type, zone)
		response = header_section + question_section + response_section
	else:
		for answers in answer_cache:
			if answers[0] == name  and answers[2] == question_type:
				cached_answer = answers[1][2:]
				cached_answer = data[:2] + cached_answer
				return cached_answer

		roots = ROOT_SERVERS
		for paths in path_cache:
			if paths[0] == name:
				roots = [paths[1]]
		print(";; ANSWER SECTION:")
		responses = RecursiveAnswer(data, roots, name, question_type)
		print("\n;; ADDITIONAL SECTION:\n")
		if responses[1]:
			response = responses[0]
			answer_cache.append([name, response, question_type])
			if(len(answer_cache) > 1000):
				answer_cache = answer_cache[1:]
		else:
			print("Unable To Find Requested")

	print("")
	return response


def run_dns_server(configpath):
	# set config directory path
	if configpath[len(configpath) - 1] != '/':
		configpath += '/'
	# set types
	SetTypes()

	# --> IP, UDP
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.bind((IP, PORT))

	while True:
		# receive 512 bytes (dns message max size)
		data, addr = sock.recvfrom(512)
		response = GetResponse(data, configpath)
		sock.sendto(response, addr)

# do not change!
if __name__ == '__main__':
    configpath = sys.argv[1]
    run_dns_server(configpath)
    