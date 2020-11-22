require "ipc"
require "json"
require "ipc/json"

class IPC::JSON
	def handle(service : AuthD::Service, event : IPC::Event::Events)
		raise "unimplemented"
	end
end

module AuthD
	class_getter requests  = [] of IPC::JSON.class
	class_getter responses = [] of IPC::JSON.class
end

class IPC::Context
	def send(fd, response : AuthD::Response)
		send fd, response.type.to_u8, response.to_json
	end
end

class IPC::Client
	def send(request : AuthD::Request)
		unless (fd = @server_fd).nil?
			send_now fd, request.type.to_u8, request.to_json
		else
			raise "Client not connected to the server"
		end
	end
end


require "./requests/*"
require "./responses/*"
