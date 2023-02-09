require "ipc/json"
require "json"

module AuthD
	class Client < IPC
		property key : String
		property server_fd : Int32 = -1

		def initialize
			super
			@key = ""
			fd = self.connect "auth"
			if fd.nil?
				raise "couldn't connect to 'auth' IPC service"
			end
			@server_fd = fd
		end

		def read
			slice = self.read @server_fd
			m = IPCMessage::TypedMessage.deserialize slice
			m.not_nil!
		end

		def get_token?(login : String, password : String) : String?
			send_now Request::GetToken.new login, password

			response = AuthD.responses.parse_ipc_json read

			if response.is_a?(Response::Token)
				response.token
			else
				nil
			end
		end

		def get_user?(login : String, password : String) : AuthD::User::Public?
			send_now Request::GetUserByCredentials.new login, password

			response = AuthD.responses.parse_ipc_json read

			if response.is_a? Response::User
				response.user
			else
				nil
			end
		end

		def get_user?(uid_or_login : Int32 | String) : ::AuthD::User::Public?
			send_now Request::GetUser.new uid_or_login

			response = AuthD.responses.parse_ipc_json read

			if response.is_a? Response::User
				response.user
			else
				nil
			end
		end

		def send_now(msg : IPC::JSON)
			m = IPCMessage::TypedMessage.new msg.type.to_u8, msg.to_json
			write @server_fd, m
		end

		def send_now(type : Request::Type, payload)
			m = IPCMessage::TypedMessage.new type.value.to_u8, payload
			write @server_fd, m
		end

		def decode_token(token)
			user, meta = JWT.decode token, @key, JWT::Algorithm::HS256

			user = ::AuthD::User::Public.from_json user.to_json

			{user, meta}
		end

		# FIXME: Extra options may be useful to implement here.
		def add_user(login : String, password : String,
			email : String?,
			phone : String?,
			profile : Hash(String, ::JSON::Any)?) : ::AuthD::User::Public | Exception

			send_now Request::AddUser.new @key, login, password, email, phone, profile

			response = AuthD.responses.parse_ipc_json read

			case response
			when Response::UserAdded
				response.user
			when Response::Error
				raise Exception.new response.reason
			else
				# Should not happen in serialized connections, but…
				# it’ll happen if you run several requests at once.
				Exception.new
			end
		end

		def validate_user(login : String, activation_key : String) : ::AuthD::User::Public | Exception
			send_now Request::ValidateUser.new login, activation_key

			response = AuthD.responses.parse_ipc_json read

			case response
			when Response::UserValidated
				response.user
			when Response::Error
				raise Exception.new response.reason
			else
				# Should not happen in serialized connections, but…
				# it’ll happen if you run several requests at once.
				Exception.new
			end
		end

		def ask_password_recovery(uid_or_login : String | Int32, email : String)
			send_now Request::AskPasswordRecovery.new uid_or_login, email
			response = AuthD.responses.parse_ipc_json read

			case response
			when Response::PasswordRecoverySent
			when Response::Error
				raise Exception.new response.reason
			else
				Exception.new
			end
		end

		def change_password(uid_or_login : String | Int32, new_pass : String, renew_key : String)
			send_now Request::PasswordRecovery.new uid_or_login, renew_key, new_pass
			response = AuthD.responses.parse_ipc_json read

			case response
			when Response::PasswordRecovered
			when Response::Error
				raise Exception.new response.reason
			else
				Exception.new
			end
		end

		def register(login : String,
			password : String,
			email : String?,
			phone : String?,
			profile : Hash(String, ::JSON::Any)?) : ::AuthD::User::Public?

			send_now Request::Register.new login, password, email, phone, profile
			response = AuthD.responses.parse_ipc_json read

			case response
			when Response::UserAdded
			when Response::Error
				raise Exception.new response.reason
			end
		end

		def mod_user(uid_or_login : Int32 | String, password : String? = nil, email : String? = nil, phone : String? = nil, avatar : String? = nil) : Bool | Exception
			request = Request::ModUser.new @key, uid_or_login

			request.password = password if password
			request.email    = email    if email
			request.phone    = phone    if phone
			request.avatar   = avatar   if avatar

			send_now request

			response = AuthD.responses.parse_ipc_json read

			case response
			when Response::UserEdited
				true
			when Response::Error
				Exception.new response.reason
			else
				Exception.new "???"
			end
		end

		def check_permission(user : Int32, service_name : String, resource_name : String) : User::PermissionLevel
			request = Request::CheckPermission.new @key, user, service_name, resource_name

			send_now request

			response = AuthD.responses.parse_ipc_json read

			case response
			when Response::PermissionCheck
				response.permission
			when Response
				raise Exception.new "unexpected response: #{response.type}"
			else
				raise Exception.new "unexpected response"
			end
		end

		def set_permission(uid : Int32, service : String, resource : String, permission : User::PermissionLevel)
			request = Request::SetPermission.new @key, uid, service, resource, permission

			send_now request

			response = AuthD.responses.parse_ipc_json read

			case response
			when Response::PermissionSet
				true
			when Response
				raise Exception.new "unexpected response: #{response.type}"
			else
				raise Exception.new "unexpected response"
			end
		end

		def search_user(user_login : String)
			send_now Request::SearchUser.new user_login
			response = AuthD.responses.parse_ipc_json read

			case response
			when Response::MatchingUsers
				response.users
			when Response::Error
				raise Exception.new response.reason
			else
				Exception.new
			end
		end

		def edit_profile_content(user : Int32 | String, new_values)
			send_now Request::EditProfileContent.new key, user, new_values
			response = AuthD.responses.parse_ipc_json read

			case response
			when Response::User
				response.user
			when Response::Error
				raise Exception.new response.reason
			else
				raise Exception.new "unexpected response"
			end
		end

		def delete(user : Int32 | String, key : String)
			send_now Request::Delete.new user, key
			delete_
		end
		def delete(user : Int32 | String, login : String, pass : String)
			send_now Request::Delete.new user, login, pass
			delete_
		end
		def delete_
			response = AuthD.responses.parse_ipc_json read
			case response
			when Response::Error
				raise Exception.new response.reason
			end
			response
		end
	end
end
