require "json"

require "jwt"

require "ipc"

require "./user.cr"

class AuthD::Exception < Exception
end

class AuthD::MalformedRequest < Exception
	getter ipc_type : Int32
	getter payload : String

	def initialize(@ipc_type, @payload)
		@message = "malformed payload"
	end
end

class AuthD::Response
	include JSON::Serializable

	property id : JSON::Any?

	annotation MessageType
	end

	class_getter type = -1
	def type
		@@type
	end

	macro inherited
		def self.type
			::AuthD::Response::Type::{{ @type.name.split("::").last.id }}
		end
	end

	macro initialize(*properties)
		def initialize(
			{% for value in properties %}
				@{{value.id}}{% if value != properties.last %},{% end %}
			{% end %}
		)
		end

		def type
			Type::{{ @type.name.split("::").last.id }}
		end
	end

	class Error < Response
		property reason : String?

		initialize :reason
	end

	class Token < Response
		property uid    : Int32
		property token  : String

		initialize :token, :uid
	end

	class User < Response
		property user   : ::AuthD::User::Public

		initialize :user
	end

	class UserAdded < Response
		property user   : ::AuthD::User::Public

		initialize :user
	end

	class UserEdited < Response
		property uid    : Int32

		initialize :uid
	end

	class UserValidated < Response
		property user   : ::AuthD::User::Public

		initialize :user
	end

	class UsersList < Response
		property users  : Array(::AuthD::User::Public)

		initialize :users
	end

	class PermissionCheck < Response
		property user       : Int32
		property service    : String
		property resource   : String
		property permission : ::AuthD::User::PermissionLevel

		initialize :service, :resource, :user, :permission
	end

	class PermissionSet < Response
		property user       : Int32
		property service    : String
		property resource   : String
		property permission : ::AuthD::User::PermissionLevel

		initialize :user, :service, :resource, :permission
	end

	class PasswordRecoverySent < Response
		property user   : ::AuthD::User::Public

		initialize :user
	end

	class PasswordRecovered < Response
		property user   : ::AuthD::User::Public

		initialize :user
	end

	class MatchingUsers < Response
		property users  : Array(::AuthD::User::Public)

		initialize :users
	end

	# This creates a Request::Type enumeration. One entry for each request type.
	{% begin %}
		enum Type
			{% for ivar in @type.subclasses %}
				{% klass = ivar.name %}
				{% name = ivar.name.split("::").last.id %}

				{% a = ivar.annotation(MessageType) %}

				{% if a %}
					{% value = a[0] %}
					{{ name }} = {{ value }}
				{% else %}
					{{ name }}
				{% end %}
			{% end %}
		end
	{% end %}

	# This is an array of all requests types.
	{% begin %}
		class_getter requests = [
			{% for ivar in @type.subclasses %}
				{% klass = ivar.name %}

				{{klass}},
			{% end %}
		]
	{% end %}

	def self.from_ipc(message : IPC::Message) : Response?
		payload = String.new message.payload
		type = Type.new message.utype.to_i

		begin
			requests.find(&.type.==(type)).try &.from_json(payload)
		rescue e : JSON::ParseException
			raise MalformedRequest.new message.utype.to_i, payload
		end
	end
end

class AuthD::Request
	include JSON::Serializable

	property id : JSON::Any?

	annotation MessageType
	end

	class_getter type = -1

	macro inherited
		def self.type
			::AuthD::Request::Type::{{ @type.name.split("::").last.id }}
		end
	end

	macro initialize(*properties)
		def initialize(
			{% for value in properties %}
				@{{value.id}}{% if value != properties.last %},{% end %}
			{% end %}
		)
		end

		def type
			Type::{{ @type.name.split("::").last.id }}
		end
	end

	class GetToken < Request
		property login      : String
		property password   : String

		initialize :login, :password
	end

	class AddUser < Request
		# Only clients that have the right shared key will be allowed
		# to create users.
		property shared_key : String

		property login      : String
		property password   : String
		property email      : String?
		property phone      : String?
		property profile    : Hash(String, JSON::Any)?

		initialize :shared_key, :login, :password, :email, :phone, :profile
	end

	class ValidateUser < Request
		property login             : String
		property activation_key    : String

		initialize :login, :activation_key
	end

	class GetUser < Request
		property user       : Int32 | String

		initialize :user
	end

	class GetUserByCredentials < Request
		property login      : String
		property password   : String

		initialize :login, :password
	end

	class ModUser < Request
		property shared_key : String

		property user       : Int32 | String
		property password   : String?
		property email      : String?
		property phone      : String?
		property avatar     : String?

		initialize :shared_key, :user
	end

	class Register < Request
		property login      : String
		property password   : String
		property email      : String?
		property phone      : String?
		property profile    : Hash(String, JSON::Any)?

		initialize :login, :password, :email, :phone, :profile
	end

	class UpdatePassword < Request
		property login      : String
		property old_password : String
		property new_password : String
	end

	class ListUsers < Request
		property token : String?
		property key : String?
	end

	class CheckPermission < Request
		property shared_key : String

		property user       : Int32 | String
		property service    : String
		property resource   : String

		initialize :shared_key, :user, :service, :resource
	end

	class SetPermission < Request
		property shared_key : String

		property user       : Int32 | String
		property service    : String
		property resource   : String
		property permission : ::AuthD::User::PermissionLevel

		initialize :shared_key, :user, :service, :resource, :permission
	end

	class PasswordRecovery < Request
		property user               : Int32 | String
		property password_renew_key : String
		property new_password       : String

		initialize :user, :password_renew_key, :new_password
	end

	class AskPasswordRecovery < Request
		property user       : Int32 | String
		property email      : String

		initialize :user, :email
	end

	class SearchUser < Request
		property user : String

		initialize :user
	end

	class EditProfile < Request
		property token : String
		property new_profile : Hash(String, JSON::Any)

		initialize :token, :new_profile
	end

	# Same as above, but doesn’t reset the whole profile, only resets elements
	# for which keys are present in `new_profile`.
	class EditProfileContent < Request
		property token      : String?

		property shared_key : String?
		property user : Int32 | String | Nil

		property new_profile : Hash(String, JSON::Any)

		initialize :shared_key, :user, :new_profile
		initialize :token, :new_profile
	end

	class EditContacts < Request
		property token : String

		property email : String?
		property phone : String?
	end

	# This creates a Request::Type enumeration. One entry for each request type.
	{% begin %}
		enum Type
			{% for ivar in @type.subclasses %}
				{% klass = ivar.name %}
				{% name = ivar.name.split("::").last.id %}

				{% a = ivar.annotation(MessageType) %}

				{% if a %}
					{% value = a[0] %}
					{{ name }} = {{ value }}
				{% else %}
					{{ name }}
				{% end %}
			{% end %}
		end
	{% end %}

	# This is an array of all requests types.
	{% begin %}
		class_getter requests = [
			{% for ivar in @type.subclasses %}
				{% klass = ivar.name %}

				{{klass}},
			{% end %}
		]
	{% end %}

	def self.from_ipc(message : IPC::Message) : Request?
		payload = String.new message.payload
		type = Type.new message.utype.to_i

		begin
			requests.find(&.type.==(type)).try &.from_json(payload)
		rescue e : JSON::ParseException
			raise MalformedRequest.new message.utype.to_i, payload
		end
	end
end

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

		def ask_password_recovery(uid_or_login : String | Int32)
			send Request::AskPasswordRecovery.new uid_or_login
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
	end
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

