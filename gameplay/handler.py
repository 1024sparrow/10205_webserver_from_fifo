import io
import os # environment variables
import json
import logging
import socket
import struct
import traceback
import weakref
import paramiko
import tornado.web
import wave
#from .users import allowed_users, allowed_ips

from concurrent.futures import ThreadPoolExecutor
from tornado.ioloop import IOLoop
from tornado.options import options
from tornado.process import cpu_count
#from webssh.utils import (
#	is_valid_ip_address, is_valid_port, is_valid_hostname, to_bytes, to_str,
#	to_int, to_ip_address, UnicodeType, is_ip_hostname, is_same_primary_domain,
#	is_valid_encoding
#)
#from webssh.worker import Worker, recycle_worker, clients
#from webssh.sound import Sound

try:
	from json.decoder import JSONDecodeError
except ImportError:
	JSONDecodeError = ValueError

try:
	from urllib.parse import urlparse
except ImportError:
	from urlparse import urlparse


DELAY = 3
DEFAULT_PORT = 22

swallow_http_errors = True
redirecting = None



"""
class PrivateKey(object):

	max_length = 16384	# rough number

	tag_to_name = {
		'RSA': 'RSA',
		'DSA': 'DSS',
		'EC': 'ECDSA',
		'OPENSSH': 'Ed25519'
	}

	def __init__(self, privatekey, password=None, filename=''):
		self.privatekey = privatekey
		self.filename = filename
		self.password = password
		self.check_length()
		self.iostr = io.StringIO(privatekey)
		self.last_exception = None

	def check_length(self):
		if len(self.privatekey) > self.max_length:
			raise InvalidValueError('Invalid key length.')

	def parse_name(self, iostr, tag_to_name):
		name = None
		for line_ in iostr:
			line = line_.strip()
			if line and line.startswith('-----BEGIN ') and \
					line.endswith(' PRIVATE KEY-----'):
				lst = line.split(' ')
				if len(lst) == 4:
					tag = lst[1]
					if tag:
						name = tag_to_name.get(tag)
						if name:
							break
		return name, len(line_)

	def get_specific_pkey(self, name, offset, password):
		self.iostr.seek(offset)
		logging.debug('Reset offset to {}.'.format(offset))

		logging.debug('Try parsing it as {} type key'.format(name))
		pkeycls = getattr(paramiko, name+'Key')
		pkey = None

		try:
			pkey = pkeycls.from_private_key(self.iostr, password=password)
		except paramiko.PasswordRequiredException:
			raise InvalidValueError('Need a passphrase to decrypt the key.')
		except (paramiko.SSHException, ValueError) as exc:
			self.last_exception = exc
			logging.debug(str(exc))

		return pkey

	def get_pkey_obj(self):
		logging.info('Parsing private key {!r}'.format(self.filename))
		name, length = self.parse_name(self.iostr, self.tag_to_name)
		if not name:
			raise InvalidValueError('Invalid key {}.'.format(self.filename))

		offset = self.iostr.tell() - length
		password = to_bytes(self.password) if self.password else None
		pkey = self.get_specific_pkey(name, offset, password)

		if pkey is None and name == 'Ed25519':
			for name in ['RSA', 'ECDSA', 'DSS']:
				pkey = self.get_specific_pkey(name, offset, password)
				if pkey:
					break

		if pkey:
			return pkey

		logging.error(str(self.last_exception))
		msg = 'Invalid key'
		if self.password:
			msg += ' or wrong passphrase "{}" for decrypting it.'.format(
					self.password)
		raise InvalidValueError(msg)




class MixinHandler(object):

	custom_headers = {
		'Server': 'TornadoServer'
	}

	html = ('<html><head><title>{code} {reason}</title></head><body>{code} '
			'{reason}</body></html>')

	def initialize(self, loop=None):
		self.check_request()
		self.loop = loop
		self.origin_policy = self.settings.get('origin_policy')

	def check_request(self):
		context = self.request.connection.context
		result = self.is_forbidden(context, self.request.host_name)
		self._transforms = []
		if result:
			self.set_status(403)
			self.finish(
				self.html.format(code=self._status_code, reason=self._reason)
			)
		elif result is False:
			to_url = self.get_redirect_url(
				self.request.host_name, options.sslport, self.request.uri
			)
			self.redirect(to_url, permanent=True)
		else:
			self.context = context

	def check_origin(self, origin):
		if self.origin_policy == '*':
			return True

		parsed_origin = urlparse(origin)
		netloc = parsed_origin.netloc.lower()
		logging.debug('netloc: {}'.format(netloc))

		host = self.request.headers.get('Host')
		logging.debug('host: {}'.format(host))

		if netloc == host:
			return True

		if self.origin_policy == 'same':
			return False
		elif self.origin_policy == 'primary':
			return is_same_primary_domain(netloc.rsplit(':', 1)[0],
										  host.rsplit(':', 1)[0])
		else:
			return origin in self.origin_policy

	def is_forbidden(self, context, hostname):
		ip = context.address[0]
		lst = context.trusted_downstream
		ip_address = None

		if lst and ip not in lst:
			logging.warning(
				'IP {!r} not found in trusted downstream {!r}'.format(ip, lst)
			)
			return True

		if context._orig_protocol == 'http':
			if redirecting and not is_ip_hostname(hostname):
				ip_address = to_ip_address(ip)
				if not ip_address.is_private:
					# redirecting
					return False

			if options.fbidhttp:
				if ip_address is None:
					ip_address = to_ip_address(ip)
				if not ip_address.is_private:
					logging.warning('Public plain http request is forbidden.')
					return True

	def get_redirect_url(self, hostname, port, uri):
		port = '' if port == 443 else ':%s' % port
		return 'https://{}{}{}'.format(hostname, port, uri)

	def set_default_headers(self):
		for header in self.custom_headers.items():
			self.set_header(*header)

	def get_value(self, name):
		value = self.get_argument(name)
		if not value:
			raise InvalidValueError('Missing value {}'.format(name))
		return value

	def get_context_addr(self):
		return self.context.address[:2]

	def get_client_addr(self):
		if options.xheaders:
			return self.get_real_client_addr() or self.get_context_addr()
		else:
			return self.get_context_addr()

	def get_real_client_addr(self):
		ip = self.request.remote_ip

		if ip == self.request.headers.get('X-Real-Ip'):
			port = self.request.headers.get('X-Real-Port')
		elif ip in self.request.headers.get('X-Forwarded-For', ''):
			port = self.request.headers.get('X-Forwarded-Port')
		else:
			# not running behind an nginx server
			return

		port = to_int(port)
		if port is None or not is_valid_port(port):
			# fake port
			port = 65535

		return (ip, port)
"""



class NotFoundHandler(tornado.web.ErrorHandler):

	def initialize(self):
		#super(NotFoundHandler, self).initialize()
		pass

	def prepare(self):
		raise tornado.web.HTTPError(404)



class IndexHandler(tornado.web.RequestHandler):
	def initialize(self, loop):
		#super(IndexHandler, self).initialize()
		self.loop = loop
		print('10205.0457')
	def head(self):
		pass
	def get(self):
		#self.write('hello boris')
		#self.finish()
		self.render('index.html')



#class WsockHandler
