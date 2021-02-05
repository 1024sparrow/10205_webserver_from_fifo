import os
import logging
import tornado.web
import tornado.ioloop

from tornado.options import options
from gameplay import handler
from gameplay.handler import (
	IndexHandler,
	#WsockHandler,
	NotFoundHandler
)
def make_handlers(loop, options):
	handlers = [
		(r'/', IndexHandler, dict(loop=loop)),
		#(r'/ws', WsockHandler, dict(loop=loop, sound=sound)),
	]
	return handlers

def make_app(handlers, settings):
	settings.update(default_handler_class=NotFoundHandler)
	return tornado.web.Application(handlers, **settings)


def app_listen(app, port, address, server_settings):
	app.listen(port, address, **server_settings)
	if not server_settings.get('ssl_options'):
		server_type = 'http'
	else:
		server_type = 'https'
		handler.redirecting = True if options.redirect else False
	logging.info(
		'Listening on {}:{} ({})'.format(address, port, server_type)
	)


def main():
	options.parse_command_line()
	loop = tornado.ioloop.IOLoop.current()
	app = make_app(make_handlers(loop, options), dict())
	app_listen(
		app,
		8080,
		'',
		dict(
			xheaders=True,
			max_body_size=1 * 1024 * 1024,
			trusted_downstream=set()
		)
	)
	loop.start()


if __name__ == '__main__':
	main()
