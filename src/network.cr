require "ipc"
require "ipc/json"

class IPC::JSON
	def handle(service : AuthD::Service)
		raise "unimplemented"
	end
end

module AuthD
	class_getter requests  = [] of IPC::JSON.class
	class_getter responses = [] of IPC::JSON.class
end

class IPC
	def schedule(fd, m : (AuthD::Request | AuthD::Response))
		schedule fd, m.type.to_u8, m.to_json
	end
end

require "./requests/*"
require "./responses/*"
