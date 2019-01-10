
import ipaddress

TYPE_DICT = {'A': 1, 'NS': 2, 'CNAME': 5, 'SOA': 6, 'MX': 15, 'TXT': 16, 'AAAA': 28}


def PrintResponse(question_type, zone, record):
		print(zone.domain + "\t" + str(zone.names[zone.domain].ttl) +\
				 "\tIN\t" + question_type + "\t" + record)


def ConstructBasics(question_type, zone, index):
	# Name: forming offset: 1100 0000 0000 1100
	name = ((1<<14|1<<15)|index).to_bytes(2, byteorder='big')
	# Type:
	typee = (TYPE_DICT[question_type]).to_bytes(2, byteorder='big')
	# Class: internet
	classs = (1).to_bytes(2, byteorder='big')
	# Time To Live:
	time_to_live = (zone.names[zone.domain].ttl).to_bytes(4, byteorder='big')

	return name + typee + classs + time_to_live


class form_response(object):


	def GetResponseA(question_type, zone, index):
		# Name | Type | Class | Time to Live
		basics = ConstructBasics(question_type, zone, index)

		# Data Length:
		data_length = (4).to_bytes(2, byteorder='big')

		pre_response = basics + data_length
		response = b''

		items_in_zone = zone.root.records(question_type).items
		for record in items_in_zone:
			PrintResponse(question_type, zone, record)
			response += pre_response
			record = record.split('.')
			for num in record:
				response += (int(num)).to_bytes(1, byteorder='big')

		return response
	

	def GetResponseNS(question_type, zone, index):
		# Name | Type | Class | Time to Live
		pre_response = ConstructBasics(question_type, zone, index)
		response = b''

		items_in_zone = zone.root.records(question_type).items
		for record in items_in_zone:
			PrintResponse(question_type, zone, record)
			# Data Length:
			data_length = (len(record.split(".")[0]) + 3).to_bytes(2, byteorder='big')
			response += pre_response + data_length
			record = record.split('.')[0]
			response += (len(record.split(".")[0])).to_bytes(1, byteorder='big')
			for char in record:
				response += (ord(char)).to_bytes(1, byteorder='big')
			response += ((1<<14|1<<15)|index).to_bytes(2, byteorder='big')

		return response


	def GetResponseCNAME(question_type, zone, index):
		# Name | Type | Class | Time to Live
		pre_response = ConstructBasics(question_type, zone, index)
		response = b''

		items_in_zone = zone.root.records(question_type).items
		for record in items_in_zone:
			PrintResponse(question_type, zone, record)
			# Data Length:
			data_length = (len(''.join(record.split('.')[:0-len(zone.domain.split('.'))])) +\
							len(record.split('.')[:0-len(zone.domain.split('.'))]) +\
							 2).to_bytes(2, byteorder='big')
			response += pre_response + data_length
			record_index = 0
			record = record.split('.')[:0-len(zone.domain.split('.'))]
			for string in record:
				response += len(string).to_bytes(1, byteorder='big')
				for char in string:
					response += (ord(char)).to_bytes(1, byteorder='big')

			response += ((1<<14|1<<15)|index).to_bytes(2, byteorder='big')

		return response


	def GetResponseSOA(question_type, zone, index):
		# Name | Type | Class | Time to Live
		pre_response = ConstructBasics(question_type, zone, index)
		response = b''

		items_in_zone = zone.root.records(question_type).items
		for record in items_in_zone:
			PrintResponse(question_type, zone, record)
			record = record.split(' ')

			response += pre_response

			# Data Length
			response += (len('.'.join(record[0].split('.')[:0-len(zone.domain.split('.'))])) + 3 +\
						len('.'.join(record[1].split('.')[:0-len(zone.domain.split('.'))])) + 3 +\
						 20).to_bytes(2, byteorder='big')

			# record[0]
			rec_0 = record[0].split('.')[:0-len(zone.domain.split('.'))]
			for string in rec_0:
				response += len(string).to_bytes(1, byteorder='big')
				for char in string:
					response += (ord(char)).to_bytes(1, byteorder='big')
			response += ((1<<14|1<<15)|index).to_bytes(2, byteorder='big')

			# record[1]
			rec_1 = record[1].split('.')[:0-len(zone.domain.split('.'))]
			for string in rec_1:
				response += len(string).to_bytes(1, byteorder='big')
				for char in string:
					response += (ord(char)).to_bytes(1, byteorder='big')
			response += ((1<<14|1<<15)|index).to_bytes(2, byteorder='big')

			# record[2]
			response += (int(record[2])).to_bytes(4, byteorder='big')
			# record[3]
			response += (int(record[3])).to_bytes(4, byteorder='big')
			# record[4]
			response += (int(record[4])).to_bytes(4, byteorder='big')
			# record[5]
			response += (int(record[5])).to_bytes(4, byteorder='big')
			# record[6]
			response += (int(record[6])).to_bytes(4, byteorder='big')

		return response

	def GetResponseMX(question_type, zone, index):
		# Name | Type | Class | Time to Live
		pre_response = ConstructBasics(question_type, zone, index)
		response = b''

		items_in_zone = zone.root.records(question_type).items
		for record in items_in_zone:
			preference = record[0]
			recordd = record[1]
			PrintResponse(question_type, zone, str(preference) + " " + recordd)

			# Data Length:
			data_length = (len(''.join(recordd.split('.')[:0-len(zone.domain.split('.'))])) +\
							len(recordd.split('.')[:0-len(zone.domain.split('.'))]) +\
							 4).to_bytes(2, byteorder='big')

			# Preference:
			preference = (preference).to_bytes(2, byteorder='big')
			response += pre_response + data_length + preference
			record_index = 0
			recordd = recordd.split('.')[:0-len(zone.domain.split('.'))]
			for string in recordd:
				response += len(string).to_bytes(1, byteorder='big')
				for char in string:
					response += (ord(char)).to_bytes(1, byteorder='big')

			response += ((1<<14|1<<15)|index).to_bytes(2, byteorder='big')

		return response


	def GetResponseTXT(question_type, zone, index):
		# Name | Type | Class | Time to Live
		pre_response = ConstructBasics(question_type, zone, index)
		response = b''

		items_in_zone = zone.root.records(question_type).items
		print(items_in_zone)
		for record in items_in_zone:
			PrintResponse(question_type, zone, record)

			record = record[1:-1]

			# Data Length:
			data_length = (len(record) + 1).to_bytes(2, byteorder='big')
			# TXT Length:
			txt_length = len(record).to_bytes(1, byteorder='big')

			response += pre_response + data_length + txt_length
			for char in record:
				response += (ord(char)).to_bytes(1, byteorder='big')

		return response
	

	def GetResponseAAAA(question_type, zone, index):
		# Name | Type | Class | Time to Live
		basics = ConstructBasics(question_type, zone, index)

		# Data Length:
		data_length = (16).to_bytes(2, byteorder='big')

		pre_response = basics + data_length
		response = b''

		items_in_zone = zone.root.records(question_type).items
		for record in items_in_zone:
			PrintResponse(question_type, zone, record)
			response += pre_response
			response += (int(ipaddress.IPv6Address(record))).to_bytes(16, byteorder='big')

		return response
