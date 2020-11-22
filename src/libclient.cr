
module AuthD
	class Client < IPC::Client
		property key : String

		def initialize
			@key = ""

			initialize "auth"
		end

		def get_token?(login : String, password : String) : String?
			send Request::GetToken.new login, password

			response = Response.from_ipc read

			if response.is_a?(Response::Token)
				response.token
			else
				nil
			end
		end

		def get_user?(login : String, password : String) : AuthD::User::Public?
			send Request::GetUserByCredentials.new login, password

			response = Response.from_ipc read

			if response.is_a? Response::User
				response.user
			else
				nil
			end
		end

		def get_user?(uid_or_login : Int32 | String) : ::AuthD::User::Public?
			send Request::GetUser.new uid_or_login

			response = Response.from_ipc read

			if response.is_a? Response::User
				response.user
			else
				nil
			end
		end

		def send(type : Request::Type, payload)
			send_now @server_fd, type.value.to_u8, payload
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
			profile : Hash(String, JSON::Any)?) : ::AuthD::User::Public | Exception

			send Request::AddUser.new @key, login, password, email, phone, profile

			response = Response.from_ipc read

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
			send Request::ValidateUser.new login, activation_key

			response = Response.from_ipc read

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
			send Request::AskPasswordRecovery.new uid_or_login, email
			response = Response.from_ipc read

			case response
			when Response::PasswordRecoverySent
			when Response::Error
				raise Exception.new response.reason
			else
				Exception.new
			end
		end

		def change_password(uid_or_login : String | Int32, new_pass : String, renew_key : String)
			send Request::PasswordRecovery.new uid_or_login, renew_key, new_pass
			response = Response.from_ipc read

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
			profile : Hash(String, JSON::Any)?) : ::AuthD::User::Public?

			send Request::Register.new login, password, email, phone, profile
			response = Response.from_ipc read

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

			send request

			response = Response.from_ipc read

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

			send request

			response = Response.from_ipc read

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

			send request

			response = Response.from_ipc read

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
			send Request::SearchUser.new user_login
			response = Response.from_ipc read

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
			send Request::EditProfileContent.new key, user, new_values
			response = Response.from_ipc read

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
			send Request::Delete.new user, key
			delete_
		end
		def delete(user : Int32 | String, login : String, pass : String)
			send Request::Delete.new user, login, pass
			delete_
		end
		def delete_
			response = Response.from_ipc read
			case response
			when Response::Error
				raise Exception.new response.reason
			end
			response
		end
	end
end
