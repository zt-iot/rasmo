#!/usr/bin/python

from flask import Flask, request, redirect
from flask_restful import Resource, Api, reqparse, abort
from focuser import Focuser
import smbus
import socket
import logging

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

app = Flask(__name__)
api = Api(app)

#log = logging.getLogger('werkzeug');
#log.setLevel(logging.ERROR)

focuser = Focuser(1)

# enable the camera adjust mode
focuser.set(focuser.OPT_MODE, 0x01)

parser = reqparse.RequestParser()
parser.add_argument('value', required=True, type=int, help='Specify a value to be passed to camera operations')

# Improvement:
# different parser for each resource 
# write a parent parser containing shared arguments and then
# extend the parser with copy()

def put_general(ops):
	ops_desc = { 
		focuser.OPT_ZOOM: "zoom",
		focuser.OPT_FOCUS: "focus",
		focuser.OPT_MOTOR_X: "pan",
		focuser.OPT_MOTOR_Y: "tilt",
		focuser.OPT_IRCUT: "IRCut"
	}

	req_args = parser.parse_args()
	req_val = req_args['value']
	if req_val < 0:
		return f"Invalid value {request.values['value']}", 400
	else:
		focuser.set(ops, req_val)
		return { f"{ops_desc[ops]} set into": req_val}

def get_camera_status():
	cur_zoom = focuser.get(focuser.OPT_ZOOM)
	cur_focus = focuser.get(focuser.OPT_FOCUS)
	cur_pan = focuser.get(focuser.OPT_MOTOR_X)
	cur_tilt = focuser.get(focuser.OPT_MOTOR_Y)
	return { 'zoom': cur_zoom,\
		 'focus': cur_focus,\
		'pan': cur_pan,\
		'tilt': cur_tilt\
	}


#class ResetControl(Resource):
#	def ResetCamera(self, arg):
#		if arg == None or arg == 'all':
#			focuser.set(focuser.OPT_MOTOR_X, 0)
#			focuser.set(focuser.OPT_MOTOR_Y, 0)
#			focuser.reset(focuser.OPT_ZOOM)
#			focuser.reset(focuser.OPT_FOCUS)
#		elif arg == 'zoom':
#			focuser.reset(focuser.OPT_ZOOM)
#		elif arg == 'focus':
#			focuser.reset(focuser.OPT_FOCUS)
#		elif arg == 'pan':
#			focuser.set(focuser.OPT_MOTOR_X, 0)
#		elif arg == 'tilt':
#			focuser.set(focuser.OPT_MOTOR_Y, 0)
#		return get_camera_status()
#
#	def put(self, **kargs):
#		arg = None
#		if kargs:
#			arg = kargs['opt_name']
#		return self.ResetCamera(arg)

class ResetControl(Resource):
	def put(self):
		focuser.set(focuser.OPT_MOTOR_X, 0)
		focuser.set(focuser.OPT_MOTOR_Y, 0)
		focuser.reset(focuser.OPT_ZOOM)
		focuser.reset(focuser.OPT_FOCUS)
		return get_camera_status()

class CameraInfo(Resource):
	def get(self):
		return get_camera_status()

class ZoomControl(Resource):
	def __init__(self):
		self.opt = focuser.OPT_ZOOM
	def get(self):
		zoom_val = focuser.get(self.opt)
		return { "Current zoom value": zoom_val }
	def put(self):
		return put_general(self.opt)
		

class FocusControl(Resource):
	def __init__(self):
		self.opt = focuser.OPT_FOCUS
	def get(self):
		return { "Current focus value": focuser.get(self.opt) }
	def put(self):
		return put_general(self.opt)

class PanControl(Resource):
	def __init__(self):
		self.opt = focuser.OPT_MOTOR_X
	def get(self):
		return { "Current PAN value": focuser.get(self.opt) }
	def put(self):
		return put_general(self.opt)

class TiltControl(Resource):
	def __init__(self):
		self.opt = focuser.OPT_MOTOR_Y
	def get(self):
		return { "Current TILT value": focuser.get(self.opt) }
	def put(self):
		return put_general(self.opt)

class IRCutControl(Resource):
	def __init__(self):
		self.opt = focuser.OPT_IRCUT
	def get(self):
		return { "Current IRCUT value": focuser.get(self.opt) }
	def put(self):
		return put_general(self.opt)


#api.add_resource(ResetControl, '/reset', '/reset/<opt_name>')
api.add_resource(ResetControl, '/reset')
api.add_resource(ZoomControl, '/zoom')
api.add_resource(FocusControl, '/focus')
api.add_resource(PanControl, '/pan')
api.add_resource(TiltControl, '/tilt')
api.add_resource(IRCutControl, '/ircut')
api.add_resource(CameraInfo, '/info')

# can't access it from other ips if you don't set host=0.0.0.0
if __name__ == '__main__':
	#app.run(debug=False, host='0.0.0.0', port=5001, ssl_context=('keys/server.crt', 'keys/server.key'))
	app.run(debug=False, host='0.0.0.0', port=5001)
