require "json"
require "uuid"

class AuthD::User
	include JSON::Serializable

	enum PermissionLevel
		None
		Read
		Edit
		Admin

		def to_json(o)
			to_s.downcase.to_json o
		end
	end

	class Contact
		include JSON::Serializable

		# the activation key is removed once the user is validated
		property activation_key : String?
		property email          : String?
		property phone          : String?

		def initialize(@email = nil, @phone = nil)
			@activation_key = UUID.random.to_s
		end
	end

	# Public.
	property login         : String
	property uid           : Int32
	property profile       : Hash(String, JSON::Any)?

	# Private.
	property contact              : Contact
	property password_hash        : String
	property password_renew_key   : String?
	# service => resource => permission level
	property permissions          : Hash(String, Hash(String, PermissionLevel))
	property configuration        : Hash(String, Hash(String, JSON::Any))
	property date_last_connection : Time? = nil
	property date_registration    : Time? = nil

	def to_token
		Token.new @login, @uid
	end

	def initialize(@uid, @login, @password_hash)
		@contact       = Contact.new
		@permissions   = Hash(String, Hash(String, PermissionLevel)).new
		@configuration = Hash(String, Hash(String, JSON::Any)).new
	end

	class Public
		include JSON::Serializable

		property login   : String
		property uid     : Int32
		property profile : Hash(String, JSON::Any)?

		property date_registration : Time?

		def initialize(@uid, @login, @profile, @date_registration)
		end
	end

	def to_public : Public
		Public.new @uid, @login, @profile, @date_registration
	end
end

